# generate-key-pair
KEY PAIR | ENCRYPT | DECRYPT  [NODE-FORGE]

```ts
import forge from 'node-forge'

const generateKeyPairAsync = async () => {
  const keyPair = forge.pki.rsa.generateKeyPair({
    bits: 4096,
  })
  const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey)
  const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey)

  return {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
  }
}

const encrypt = async (data: string, publicKeyPem: string) => {
  // const publicKey = forge.pki.publicKeyFromPem(publicKeyPem)
  // const encrypted = publicKey.encrypt(forge.util.encodeUtf8(data), 'RSA-OAEP')
  // return forge.util.encode64(encrypted)

  const aesKey = forge.random.getBytesSync(32) // 256 bits
  const iv = forge.random.getBytesSync(12) // 96 bits

  const cipher = forge.cipher.createCipher('AES-GCM', aesKey)
  cipher.start({
    iv, // 96 bits
    tagLength: 128, // 128 bits
  })
  cipher.update(forge.util.createBuffer(data, 'utf8'))
  cipher.finish()

  const encryptedMessage = cipher.output

  const tag = cipher.mode.tag.getBytes()

  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem)
  const encryptedAesKey = publicKey.encrypt(aesKey, 'RSA-OAEP')

  return {
    encryptedMessage: forge.util.encode64(encryptedMessage.getBytes()),
    iv: forge.util.encode64(iv),
    tag: forge.util.encode64(tag),
    encryptedAesKey: forge.util.encode64(encryptedAesKey),
  }
}

const decrypt = async (
  encryptedData: {
    encryptedAesKey: string
    iv: string
    tag: any
    encryptedMessage: string
  },
  privateKeyPem: string
) => {
  // const privateKey = forge.pki.privateKeyFromPem(privateKeyPem)
  // const decrypted = privateKey.decrypt(
  //   forge.util.decode64(encryptedData),
  //   'RSA-OAEP'
  // )
  // return forge.util.decodeUtf8(decrypted)

  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem)

  const encryptedAesKey = forge.util.decode64(encryptedData.encryptedAesKey)
  const aesKey = privateKey.decrypt(encryptedAesKey, 'RSA-OAEP')

  const iv = forge.util.createBuffer(forge.util.decode64(encryptedData.iv))
  const tag = forge.util.createBuffer(forge.util.decode64(encryptedData.tag))
  const encryptedMessage = forge.util.createBuffer(
    forge.util.decode64(encryptedData.encryptedMessage)
  )

  const decipher = forge.cipher.createDecipher('AES-GCM', aesKey)
  decipher.start({ iv, tag })
  decipher.update(encryptedMessage)
  decipher.finish()

  const decryptedMessageBytes = decipher.output.getBytes()
  const decryptedMessage = Buffer.from(
    decryptedMessageBytes,
    'binary' as BufferEncoding
  ).toString('utf8')

  return decryptedMessage
}

export { generateKeyPairAsync, encrypt, decrypt }

```
