using CryptoHelper;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace CryptoHelper
{
    public class AESCore : ICrypto
    {
        private Aes Aes { get; }
        public CryptoCoreInfo Info { get; }
        public AESCore ()
        {
            Aes = Aes.Create();
            Aes.KeySize = 256;
            Aes.GenerateKey();
            Aes.GenerateIV();
            Info = CreateDetails(Aes.Key, Aes.IV);
            Aes.Key = Info.AesDetail!.AesKeyValue.Key;
            Aes.IV = Info.AesDetail!.AesKeyValue.Iv;
        }
        public AESCore(byte[] key, byte[] iv)
        {
            Aes = Aes.Create();
            Aes.KeySize = 256;
            Info = CreateDetails(key, iv);
            Aes.Key = Info.AesDetail!.AesKeyValue.Key;
            Aes.IV = Info.AesDetail!.AesKeyValue.Iv;
        }


        private CryptoCoreInfo CreateDetails(byte[] key, byte[] iv)
        {
            return new CryptoCoreInfo()
            {
                AesDetail = new AesDetail(key, iv)
                {
                    Aes = Aes
                },
                EncryptionType = EncryptionType.Aes,
                KeyType = KeyType.SymmetricKey
            };
        }
        #region encryption logic
        public byte[] EncryptString(string bytes)
        {
            return EncryptContent(bytes);
        }

        public byte[] EncryptBytes(byte[] bytes)
        {
            return EncryptContent(Utility.BytesToString(bytes));
        }

        public string DecryptString(byte[] bytes)
        {
            return DecryptContent(bytes);
        }

        public byte[] DecryptBytes(byte[] bytes)
        {
            return Utility.StringToBytes(DecryptContent(bytes));
        }

        private byte[] EncryptContent(string content)
        {
            if (content == null || content.Length <= 0)
            {
                throw new ArgumentNullException("content");
            }

            byte[] encrypted;

            ICryptoTransform encryptor = Aes.CreateEncryptor(Aes.Key, Aes.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(content);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }

            return encrypted;
        }

        private string DecryptContent(byte[] bytes)
        {
            if (bytes == null || bytes.Length <= 0)
            {
                throw new ArgumentNullException("bytes");
            }

            string? plaintext;

            ICryptoTransform decryptor = Aes.CreateDecryptor(Aes.Key, Aes.IV);

            using (MemoryStream msDecrypt = new MemoryStream(bytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

            return plaintext;
        }
        #endregion
    }
}