using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoHelper
{
    public interface ICrypto
    {

        byte[] EncryptString(string content);
        string DecryptString(byte[] bytes);
        byte[] EncryptBytes(byte[] bytes);
        byte[] DecryptBytes(byte[] bytes);
    }
}
