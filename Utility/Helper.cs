using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoHelper
{
    public  class AESHelper
    {
        public static byte[] EncryptContent(string symmetricKey, string secret, string data)
        {

            symmetricKey = new string(symmetricKey.Take(32).ToArray());

            secret = new string(secret.Take(16).ToArray());

            var key = Encoding.UTF8.GetBytes(symmetricKey);
            var iv = Encoding.UTF8.GetBytes(secret);

            ICrypto encryptClient = new AESCore(key, iv);
            var encrypt = encryptClient.EncryptString(data);

            return encrypt;

        }

        public static string DecryptContent(string symmetricKey, string secret, byte[] data)
        {

            secret = new string(secret.Take(16).ToArray());

            var key = Encoding.UTF8.GetBytes(symmetricKey);
            var iv = Encoding.UTF8.GetBytes(secret);

            ICrypto decryptClient = new AESCore(key, iv);
            var decrypt = decryptClient.DecryptString(data);

            return decrypt;

           
        }
    }
    public class RSAHelper
    {

        public static byte[] EncryptContent(string PublicKeyFile, string data)
        {
            ICrypto cryptoNetWithPublicKey = new RSACore (new FileInfo(PublicKeyFile));
            var encryptWithPublicKey = cryptoNetWithPublicKey.EncryptString(data);


            return encryptWithPublicKey;


        }

        public static string DecryptContent(string PrivateKeyFile, byte[] data)
        {
           

            ICrypto cryptoNetWithPrivateKey = new RSACore(new FileInfo(PrivateKeyFile));
            var decryptWithPrivateKey = cryptoNetWithPrivateKey.DecryptString(data);

            return decryptWithPrivateKey;
        }
    }
}
