
    def sendMsg(self,toRipe):
        sqlLock.acquire()
        t = ('doingpow','findingpubkey',toRipe)
        sqlSubmitQueue.put('UPDATE sent SET status=? WHERE status=? AND toripe=?')
        sqlSubmitQueue.put(t)
        queryreturn = sqlReturnQueue.get()

        t = ('doingpow',toRipe)
        sqlSubmitQueue.put('SELECT toaddress, fromaddress, subject, message, ackdata FROM sent WHERE status=? AND toripe=?')
        sqlSubmitQueue.put(t)
        queryreturn = sqlReturnQueue.get()
        sqlLock.release()
        for row in queryreturn:
            toaddress, fromaddress, subject, message, ackdata = row
            ackdataForWhichImWatching[ackdata] = 0
            toStatus,toAddressVersionNumber,toStreamNumber,toHash = decodeAddress(toaddress)
            fromStatus,fromAddressVersionNumber,fromStreamNumber,fromHash = decodeAddress(fromaddress)
            self.emit(SIGNAL("updateSentItemStatusByAckdata(PyQt_PyObject,PyQt_PyObject)"),ackdata,'Doing work necessary to send the message.')
            printLock.acquire()
            print 'Found a message in our database that needs to be sent with this pubkey.'
            print 'First 150 characters of message:', message[:150]
            printLock.release()
            embeddedTime = pack('>I',(int(time.time())+random.randrange(-300, 300)))#the current time plus or minus five minutes. We will use this time both for our message and for the ackdata packed within our message.
            if fromAddressVersionNumber == 2:
                payload = '\x01' #Message version.
                payload += encodeVarint(fromAddressVersionNumber)
                payload += encodeVarint(fromStreamNumber)
                payload += '\x00\x00\x00\x01' #Bitfield of features and behaviors that can be expected from me. (See https://bitmessage.org/wiki/Protocol_specification#Pubkey_bitfield_features  )

                #We need to convert our private keys to public keys in order to include them.
                try:
                    privSigningKeyBase58 = config.get(fromaddress, 'privsigningkey')
                    privEncryptionKeyBase58 = config.get(fromaddress, 'privencryptionkey')
                except:
                    self.emit(SIGNAL("updateSentItemStatusByAckdata(PyQt_PyObject,PyQt_PyObject)"),ackdata,'Error! Could not find sender address (your address) in the keys.dat file.')
                    continue

                privSigningKeyHex = decodeWalletImportFormat(privSigningKeyBase58).encode('hex')
                privEncryptionKeyHex = decodeWalletImportFormat(privEncryptionKeyBase58).encode('hex')

                pubSigningKey = highlevelcrypto.privToPub(privSigningKeyHex).decode('hex')
                pubEncryptionKey = highlevelcrypto.privToPub(privEncryptionKeyHex).decode('hex')

                payload += pubSigningKey[1:] #The \x04 on the beginning of the public keys are not sent. This way there is only one acceptable way to encode and send a public key.
                payload += pubEncryptionKey[1:]

                payload += toHash #This hash will be checked by the receiver of the message to verify that toHash belongs to them. This prevents a Surreptitious Forwarding Attack.
                payload += '\x02' #Type 2 is simple UTF-8 message encoding as specified on the Protocol Specification on the Bitmessage Wiki.
                messageToTransmit = 'Subject:' + subject + '\n' + 'Body:' + message
                payload += encodeVarint(len(messageToTransmit))
                payload += messageToTransmit
                fullAckPayload = self.generateFullAckMessage(ackdata,toStreamNumber,embeddedTime)#The fullAckPayload is a normal msg protocol message with the proof of work already completed that the receiver of this message can easily send out.
                payload += encodeVarint(len(fullAckPayload))
                payload += fullAckPayload
                signature = highlevelcrypto.sign(payload,privSigningKeyHex)
                payload += encodeVarint(len(signature))
                payload += signature


            #We have assembled the data that will be encrypted. Now let us fetch the recipient's public key out of our database and do the encryption.

            if toAddressVersionNumber == 2:
                sqlLock.acquire()
                sqlSubmitQueue.put('SELECT transmitdata FROM pubkeys WHERE hash=?')
                sqlSubmitQueue.put((toRipe,))
                queryreturn = sqlReturnQueue.get()
                sqlLock.release()

                for row in queryreturn:
                    pubkeyPayload, = row

                #The pubkey is stored the way we originally received it which means that we need to read beyond things like the nonce and time to get to the public keys.
                readPosition = 8 #to bypass the nonce
                readPosition += 4 #to bypass the embedded time
                readPosition += 1 #to bypass the address version whose length is definitely 1
                streamNumber, streamNumberLength = decodeVarint(pubkeyPayload[readPosition:readPosition+10])
                readPosition += streamNumberLength
                behaviorBitfield = pubkeyPayload[readPosition:readPosition+4]
                readPosition += 4 #to bypass the bitfield of behaviors
                #pubSigningKeyBase256 = pubkeyPayload[readPosition:readPosition+64] #We don't use this key for anything here.
                readPosition += 64
                pubEncryptionKeyBase256 = pubkeyPayload[readPosition:readPosition+64]
                readPosition += 64
                encrypted = highlevelcrypto.encrypt(payload,"04"+pubEncryptionKeyBase256.encode('hex'))


            nonce = 0
            trialValue = 99999999999999999999

            encodedStreamNumber = encodeVarint(toStreamNumber)
            #We are now dropping the unencrypted data in payload since it has already been encrypted and replacing it with the encrypted payload that we will send out.
            payload = embeddedTime + encodedStreamNumber + encrypted
            target = 2**64 / ((len(payload)+payloadLengthExtraBytes+8) * averageProofOfWorkNonceTrialsPerByte)
            print '(For msg message) Doing proof of work. Target:', target
            powStartTime = time.time()
            initialHash = hashlib.sha512(payload).digest()
            while trialValue > target:
                nonce += 1
                trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
            print '(For msg message) Found proof of work', trialValue, 'Nonce:', nonce
            try:
                print 'POW took', int(time.time()-powStartTime), 'seconds.', nonce/(time.time()-powStartTime), 'nonce trials per second.'
            except:
                pass
            payload = pack('>Q',nonce) + payload

            inventoryHash = calculateInventoryHash(payload)
            objectType = 'msg'
            inventory[inventoryHash] = (objectType, toStreamNumber, payload, int(time.time()))
            self.emit(SIGNAL("updateSentItemStatusByAckdata(PyQt_PyObject,PyQt_PyObject)"),ackdata,'Message sent. Waiting on acknowledgement. Sent on ' + strftime(config.get('bitmessagesettings', 'timeformat'),localtime(int(time.time()))))
            print 'sending inv (within sendmsg function)'
            broadcastToSendDataQueues((streamNumber, 'sendinv', inventoryHash))

            #Update the status of the message in the 'sent' table to have a 'sent' status
            sqlLock.acquire()
            t = ('sentmessage',toaddress, fromaddress, subject, message,'doingpow')
            sqlSubmitQueue.put('UPDATE sent SET status=? WHERE toaddress=? AND fromaddress=? AND subject=? AND message=? AND status=?')
            sqlSubmitQueue.put(t)
            queryreturn = sqlReturnQueue.get()

            t = (toRipe,)
            sqlSubmitQueue.put('''UPDATE pubkeys SET usedpersonally='yes' WHERE hash=?''')
            sqlSubmitQueue.put(t)
            queryreturn = sqlReturnQueue.get()

            sqlLock.release()

