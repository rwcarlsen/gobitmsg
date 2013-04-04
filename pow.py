
def requestPubKey(self,addressVersionNumber,streamNumber,ripe):
  payload = pack('>I',int(time.time()))
  payload += encodeVarint(addressVersionNumber)
  payload += encodeVarint(streamNumber)
  payload += ripe

  print 'making request for pubkey with ripe:', ripe.encode('hex')

  nonce = 0
  trialValue = 99999999999999999999

  print 'Doing proof-of-work necessary to send getpubkey message.'

  target = 2**64 / ((len(payload)+payloadLengthExtraBytes+8) * averageProofOfWorkNonceTrialsPerByte)
  initialHash = hashlib.sha512(payload).digest()
  while trialValue > target:
    nonce += 1
    trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])

  print 'Found proof of work', trialValue, 'Nonce:', nonce

  payload = pack('>Q',nonce) + payload
  inventoryHash = calculateInventoryHash(payload)

  objectType = 'getpubkey'
  inventory[inventoryHash] = (objectType, streamNumber, payload, int(time.time()))

  print 'sending inv (for the getpubkey message)'

  broadcastToSendDataQueues((streamNumber, 'sendinv', inventoryHash))

  self.emit(SIGNAL("updateStatusBar(PyQt_PyObject)"),'Broacasting the public key request. This program will auto-retry if they are offline.')
    self.emit(SIGNAL("updateSentItemStatusByHash(PyQt_PyObject,PyQt_PyObject)"),ripe,'Sending public key request. Waiting for reply. Requested at ' + strftime(config.get('bitmessagesettings', 'timeformat'),localtime(int(time.time()))))

def generateFullAckMessage(self,ackdata,toStreamNumber,embeddedTime):
  nonce = 0
  trialValue = 99999999999999999999
  encodedStreamNumber = encodeVarint(toStreamNumber)
  payload = embeddedTime + encodedStreamNumber + ackdata
  target = 2**64 / ((len(payload)+payloadLengthExtraBytes+8) * averageProofOfWorkNonceTrialsPerByte)
  print '(For ack message) Doing proof of work...'
  powStartTime = time.time()
  initialHash = hashlib.sha512(payload).digest()
  while trialValue > target:
    nonce += 1
    trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
  print '(For ack message) Found proof of work', trialValue, 'Nonce:', nonce
  print 'POW took', int(time.time()-powStartTime), 'seconds.', nonce/(time.time()-powStartTime), 'nonce trials per second.'
  payload = pack('>Q',nonce) + payload
  headerData = '\xe9\xbe\xb4\xd9' #magic bits, slighly different from Bitcoin's magic bits.
  headerData += 'msg\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  headerData += pack('>L',len(payload))
  headerData += hashlib.sha512(payload).digest()[:4]
  return headerData + payload

def doPOWForMyV2Pubkey(self,myAddress): #This function also broadcasts out the pubkey message once it is done with the POW
  status,addressVersionNumber,streamNumber,hash = decodeAddress(myAddress)
  embeddedTime = int(time.time())+random.randrange(-300, 300) #the current time plus or minus five minutes
  payload = pack('>I',(embeddedTime))
  payload += encodeVarint(2) #Address version number
  payload += encodeVarint(streamNumber)
  payload += '\x00\x00\x00\x01' #bitfield of features supported by me (see the wiki).

  try:
    privSigningKeyBase58 = config.get(myAddress, 'privsigningkey')
    privEncryptionKeyBase58 = config.get(myAddress, 'privencryptionkey')
  except Exception, err:
    sys.stderr.write('Error within doPOWForMyV2Pubkey. Could not read the keys from the keys.dat file for a requested address. %s\n' % err)
    return

  privSigningKeyHex = decodeWalletImportFormat(privSigningKeyBase58).encode('hex')
  privEncryptionKeyHex = decodeWalletImportFormat(privEncryptionKeyBase58).encode('hex')
  pubSigningKey = highlevelcrypto.privToPub(privSigningKeyHex).decode('hex')
  pubEncryptionKey = highlevelcrypto.privToPub(privEncryptionKeyHex).decode('hex')

  payload += pubSigningKey[1:]
  payload += pubEncryptionKey[1:]

  #Do the POW for this pubkey message
  nonce = 0
  trialValue = 99999999999999999999
  target = 2**64 / ((len(payload)+payloadLengthExtraBytes+8) * averageProofOfWorkNonceTrialsPerByte)
  print '(For pubkey message) Doing proof of work...'
  initialHash = hashlib.sha512(payload).digest()
  while trialValue > target:
    nonce += 1
    trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
  print '(For pubkey message) Found proof of work', trialValue, 'Nonce:', nonce

  payload = pack('>Q',nonce) + payload
  t = (hash,True,payload,embeddedTime,'no')
  sqlLock.acquire()
  sqlSubmitQueue.put('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''')
  sqlSubmitQueue.put(t)
  queryreturn = sqlReturnQueue.get()
  sqlLock.release()

  inventoryHash = calculateInventoryHash(payload)
  objectType = 'pubkey'
  inventory[inventoryHash] = (objectType, streamNumber, payload, embeddedTime)

  print 'broadcasting inv with hash:', inventoryHash.encode('hex')
  broadcastToSendDataQueues((streamNumber, 'sendinv', inventoryHash))

def sendBroadcast(self):
  sqlLock.acquire()
  t = ('broadcastpending',)
  sqlSubmitQueue.put('SELECT fromaddress, subject, message, ackdata FROM sent WHERE status=?')
  sqlSubmitQueue.put(t)
  queryreturn = sqlReturnQueue.get()
  sqlLock.release()
  for row in queryreturn:
    fromaddress, subject, body, ackdata = row
    status,addressVersionNumber,streamNumber,ripe = decodeAddress(fromaddress)
    if addressVersionNumber == 2:
      #We need to convert our private keys to public keys in order to include them.
      try:
        privSigningKeyBase58 = config.get(fromaddress, 'privsigningkey')
        privEncryptionKeyBase58 = config.get(fromaddress, 'privencryptionkey')
      except:
        self.emit(SIGNAL("updateSentItemStatusByAckdata(PyQt_PyObject,PyQt_PyObject)"),ackdata,'Error! Could not find sender address (your address) in the keys.dat file.')
        continue

      privSigningKeyHex = decodeWalletImportFormat(privSigningKeyBase58).encode('hex')
      privEncryptionKeyHex = decodeWalletImportFormat(privEncryptionKeyBase58).encode('hex')

      pubSigningKey = highlevelcrypto.privToPub(privSigningKeyHex).decode('hex') #At this time these pubkeys are 65 bytes long because they include the encoding byte which we won't be sending in the broadcast message.
      pubEncryptionKey = highlevelcrypto.privToPub(privEncryptionKeyHex).decode('hex')

      payload = pack('>I',(int(time.time())+random.randrange(-300, 300)))#the current time plus or minus five minutes
      payload += encodeVarint(1) #broadcast version
      payload += encodeVarint(addressVersionNumber)
      payload += encodeVarint(streamNumber)
      payload += '\x00\x00\x00\x01' #behavior bitfield
      payload += pubSigningKey[1:]
      payload += pubEncryptionKey[1:]
      payload += ripe
      payload += '\x02' #message encoding type
      payload += encodeVarint(len('Subject:' + subject + '\n' + 'Body:' + body))  #Type 2 is simple UTF-8 message encoding.
      payload += 'Subject:' + subject + '\n' + 'Body:' + body

      signature = highlevelcrypto.sign(payload,privSigningKeyHex)
      payload += encodeVarint(len(signature))
      payload += signature

      nonce = 0
      trialValue = 99999999999999999999
      target = 2**64 / ((len(payload)+payloadLengthExtraBytes+8) * averageProofOfWorkNonceTrialsPerByte)
      print '(For broadcast message) Doing proof of work...'
      self.emit(SIGNAL("updateSentItemStatusByAckdata(PyQt_PyObject,PyQt_PyObject)"),ackdata,'Doing work necessary to send broadcast...')
      initialHash = hashlib.sha512(payload).digest()
      while trialValue > target:
        nonce += 1
        trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
      print '(For broadcast message) Found proof of work', trialValue, 'Nonce:', nonce

      payload = pack('>Q',nonce) + payload

      inventoryHash = calculateInventoryHash(payload)
      objectType = 'broadcast'
      inventory[inventoryHash] = (objectType, streamNumber, payload, int(time.time()))
      print 'sending inv (within sendBroadcast function)'
      broadcastToSendDataQueues((streamNumber, 'sendinv', inventoryHash))

      self.emit(SIGNAL("updateSentItemStatusByAckdata(PyQt_PyObject,PyQt_PyObject)"),ackdata,'Broadcast sent at '+strftime(config.get('bitmessagesettings', 'timeformat'),localtime(int(time.time()))))

      #Update the status of the message in the 'sent' table to have a 'broadcastsent' status
      sqlLock.acquire()
      t = ('broadcastsent',int(time.time()),fromaddress, subject, body,'broadcastpending')
      sqlSubmitQueue.put('UPDATE sent SET status=?, lastactiontime=? WHERE fromaddress=? AND subject=? AND message=? AND status=?')
      sqlSubmitQueue.put(t)
      queryreturn = sqlReturnQueue.get()
      sqlLock.release()

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
    print 'Found a message in our database that needs to be sent with this pubkey.'
    print 'First 150 characters of message:', message[:150]
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

