using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SiretT {
    public class Crypto {
        public static string Encrypt(string InputString, string SecretKey, CipherMode CyphMode) {
            try {
                TripleDESCryptoServiceProvider Des = new TripleDESCryptoServiceProvider();
                //Put the string into a byte array
                byte[] InputbyteArray = Encoding.UTF8.GetBytes(InputString);
                //Create the crypto objects, with the key, as passed in
                MD5CryptoServiceProvider hashMD5 = new MD5CryptoServiceProvider();
                Des.Key = hashMD5.ComputeHash(ASCIIEncoding.ASCII.GetBytes(SecretKey));
                Des.Mode = CyphMode;
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, Des.CreateEncryptor(), CryptoStreamMode.Write);
                //Write the byte array into the crypto stream
                //(It will end up in the memory stream)
                cs.Write(InputbyteArray, 0, InputbyteArray.Length);
                cs.FlushFinalBlock();
                //Get the data back from the memory stream, and into a string
                StringBuilder ret = new StringBuilder();
                byte[] b = ms.ToArray();
                ms.Close();
                int I = 0;
                for (I = 0; I <= b.GetUpperBound(0); I++) {
                    //Format as hex
                    ret.AppendFormat("{0:X2}", b[I]);
                }
                return ret.ToString();

            } catch (System.Security.Cryptography.CryptographicException generatedExceptionName) {
                return "";
            }
        }

        public static string Decrypt(string p_InputString, string p_SecretKey, CipherMode p_CyphMode) {
            if (String.IsNullOrEmpty(p_InputString)) {
                return String.Empty;
            } else {
                StringBuilder ret = new StringBuilder();
                byte[] InputbyteArray = new byte[Convert.ToInt32(p_InputString.Length) / 2];
                TripleDESCryptoServiceProvider Des = new TripleDESCryptoServiceProvider();
                MD5CryptoServiceProvider hashMD5 = new MD5CryptoServiceProvider();
                try {
                    Des.Key = hashMD5.ComputeHash(ASCIIEncoding.ASCII.GetBytes(p_SecretKey));
                    Des.Mode = p_CyphMode;
                    for (int X = 0; X <= InputbyteArray.Length - 1; X++) {
                        Int32 IJ = (Convert.ToInt32(p_InputString.Substring(X * 2, 2), 16));
                        ByteConverter BT = new ByteConverter();
                        InputbyteArray[X] = new byte();
                        InputbyteArray[X] = Convert.ToByte(BT.ConvertTo(IJ, typeof(byte)));
                    }
                    MemoryStream ms = new MemoryStream();
                    CryptoStream cs = new CryptoStream(ms, Des.CreateDecryptor(), CryptoStreamMode.Write);
                    //Flush the data through the crypto stream into the memory stream
                    cs.Write(InputbyteArray, 0, InputbyteArray.Length);
                    cs.FlushFinalBlock();
                    //Get the decrypted data back from the memory stream
                    byte[] B = ms.ToArray();
                    ms.Close();
                    for (int I = 0; I <= B.GetUpperBound(0); I++) {
                        ret.Append(Convert.ToChar(B[I]));
                    }
                } catch (Exception ex) {
                    //   ME.Publish("SF.Utils.Utils", "DecryptString", ex, ManageException_Enumerators.ErrorLevel.FatalError);
                    return String.Empty;
                }
                return ret.ToString();
            }
        }
    }
}
