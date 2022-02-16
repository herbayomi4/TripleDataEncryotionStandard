using System;
using System.Security.Cryptography;
using System.Collections;
using System.Text;

class Members
{
    static void Main(string[] args)
    {
        string encryptedPassword = string.Empty; string hexPassword = string.Empty;
        string password = "abcxyz12";
        string value = password.ToUpper().Substring(0, 8).PadRight(8);
        string key = password.ToUpper().Substring(0, 8).PadRight(16);

        hexPassword = TripleDES(value, key);

        //PART 2

        string nextChallenge = "01234567";
        nextChallenge = nextChallenge.ToUpper().Substring(0, 8).PadRight(8);

        encryptedPassword = SingleDES(nextChallenge, hexPassword);

        Console.WriteLine(encryptedPassword);

    }    // EXPECTED RESULT 9CC5530A38A7B667


    static string TripleDES(string value, string key)
    {
        string res = string.Empty;
        TripleDESCryptoServiceProvider tDES = new TripleDESCryptoServiceProvider();

        try
        {
            byte[] keyBytes = ASCIIEncoding.ASCII.GetBytes(key);
            byte[] valueBytes = ASCIIEncoding.ASCII.GetBytes(value);

            tDES.Key = keyBytes;
            tDES.Mode = CipherMode.ECB;
            tDES.Padding = PaddingMode.PKCS7;

            ICryptoTransform trans = tDES.CreateEncryptor();

            res = BitConverter.ToString(trans.TransformFinalBlock(valueBytes, 0, valueBytes.Length));
            res = res.Replace("-", "").Substring(0, 16);
        }
        catch (CryptographicException ex)
        {
            res = $"Unable to successfully do a 3DES Encryption of the password with error: {ex.Message}";
        }

        return res;
    }

    static string SingleDES(string value, string key)
    {
        string result = string.Empty;
        DESCryptoServiceProvider DES = new DESCryptoServiceProvider();

        try
        {
            byte[] keyBytes = HexToBinary(key);

            byte[] valueBytes = ASCIIEncoding.ASCII.GetBytes(value);

            DES.Key = keyBytes;
            DES.Mode = CipherMode.ECB;
            DES.Padding = PaddingMode.PKCS7;

            ICryptoTransform trans = DES.CreateEncryptor();

            result = BitConverter.ToString(trans.TransformFinalBlock(valueBytes, 0, valueBytes.Length));
            result = result.Replace("-", "").Substring(0, 16);
        }
        catch (CryptographicException ex)
        {
            result = $"Unable to successfully do the final DES Encryption with error: {ex.Message}";
        }
        return result;
    }

    static byte[] HexToBinary(string key)
    {
        byte[] res = new byte[key.Length / 2];

        for (int i = 0; i < key.Length; i += 2)
        {
            res[i / 2] = Convert.ToByte(key.Substring(i, 2), 16);
        }

        string.Join("", res);

        return res;
    }

}