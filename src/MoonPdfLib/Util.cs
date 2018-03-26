/*! MoonPdfLib - Provides a WPF user control to display PDF files
Copyright (C) 2013  (see AUTHORS file)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
!*/
using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MoonPdfLib
{
    public class Util
    {
        public static Logger log = LogManager.GetCurrentClassLogger();

        #region 路徑解析
        // 判斷此路徑是否位於加密盤的根目錄
        public static bool IsInDriveRootDirectory(string path)
        {
            try
            {
                path = path.TrimStart('\\');
                if (path.Contains("\\"))
                    return false; // ex: \123\234 -> 123\234
                else
                    return true; // ex: \123 -> 123
            }
            catch (Exception ex)
            {
                log.Error(ex.ToString());
                return false;
            }
        }

        // 判斷此路徑是否位於資料夾的根目錄
        public static bool IsInFolderRootDirectory(string path, string folderName)
        {
            try
            {
                string rootDir = "\\" + folderName + "\\";
                if (path.StartsWith(rootDir))
                {
                    path = path.Substring(rootDir.Length);
                    if (path.Contains("\\"))
                        return false; // ex: \Share\123@Jolin\456 -> 123@Jolin\456
                    else
                        return true; // ex: \Share\123@Jolin -> 123@Jolin
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                log.Error(ex.ToString());
                return false;
            }
        }

        // 判斷此路徑是否位於ERPPro@Admin資料夾下
        public static bool IsInERPProFolder(string fileName, string folderName)
        {
            try
            {
                if (fileName.Contains("\\" + folderName + "\\ERPPro@Admin\\")) // ex: \Share\ERPPro@Admin\
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                log.Error(ex.ToString());
                return false;
            }
        }

        // 判斷兩個路徑是否位於同一個目錄下
        public static bool IsInSameDirectory(string firstPath, string secondPath)
        {
            try
            {
                if (firstPath.Substring(0, firstPath.LastIndexOf('\\')) == secondPath.Substring(0, secondPath.LastIndexOf('\\')))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                log.Error(ex.ToString());
                return false;
            }
        }
        #endregion
    }

    public class CryptFunction
    {
        public static string MD5(string input)
        {
            // Use input string to calculate MD5 hash.
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = md5.ComputeHash(inputBytes);

            // Convert the byte array to hexadecimal string.
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2")); // 輸出128 bits = 16 bytes -> 32位Hex字串
            }
            return sb.ToString();
        }

        public static byte[] AESEncrypt(byte[] input, byte[] key)
        {
            try
            {
                // 設置AES參數
                //SymmetricAlgorithm aes = Rijndael.Create(); // .net 2.0
                //RijndaelManaged aes = new RijndaelManaged(); // .net 2.0
                AesCryptoServiceProvider aes = new AesCryptoServiceProvider(); // .net 3.5
                aes.KeySize = 256; // 密鑰長度: 128/192/256 bits
                aes.BlockSize = 128; // 區塊長度: 128 bits
                aes.Key = key; // 一定要確定長度是256 bits(32 bytes)
                aes.IV = new byte[aes.BlockSize / 8]; // 初始向量長度: 128 bits (16 bytes)
                aes.Mode = CipherMode.ECB; // 區塊加解密模式: ECB/CBC
                aes.Padding = PaddingMode.Zeros; // 填補類型: Zeros/PKCS7

                // 加密資料
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] output = null;
                        csEncrypt.Write(input, 0, input.Length); // input長度可以不用為AES加解密分塊大小16的倍數，不足的部分會自動填補。
                        csEncrypt.FlushFinalBlock(); // 呼叫FlushFinalBlock以完成刷新緩衝區，且一定要在對msEncrypt取值之前，否則無法進行填補作業。
                        output = msEncrypt.ToArray(); // 所以有兩種作法: 1.在using CryptoStream區塊裡呼叫FlushFinalBlock ，然後就可對msEncrypt取值。
                        return output;
                    }
                    //output = msEncrypt.ToArray(); // 2.在using CryptoStream區塊外對msEncrypt取值，因為呼叫 Close 方法將會自動呼叫FlushFinalBlock，而using區塊結束後會自動呼叫Close方法。
                }
            }
            catch (Exception ex)
            {
                Util.log.Error(ex.ToString());
                return null;
            }
        }

        public static byte[] AESDecrypt(byte[] input, byte[] key)
        {
            try
            {
                // 設置AES參數
                AesCryptoServiceProvider aes = new AesCryptoServiceProvider(); // .net 3.5
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Key = key; // 一定要確定長度是256 bits(32 bytes)
                aes.IV = new byte[aes.BlockSize / 8];
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.Zeros;

                // 解密資料
                using (MemoryStream ms = new MemoryStream(input))
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    byte[] output = new byte[input.Length];
                    cs.Read(output, 0, output.Length); // input長度一定要是AES加解密分塊大小16的倍數，否則會有Exception
                    return output;
                }
            }
            catch (Exception ex)
            {
                Util.log.Error(ex.ToString());
                return null;
            }
        }
    }

    public class FileHeader
    {
        private int m_HeaderLength = 106;

        private const string m_startIdentifier = "%HS%";
        private const string m_endIdentifier = "%HE%";
        private int m_HeaderVersion; // 0: 51bytes long header version

        private string m_fileID;
        private long m_fileLength; // 明文長度
        private int m_fileType; // 0: Non-Encrypted File, 1: Encrypted File
        private int m_encryptAlgorithm; // 0: None, 1: AES 128-bit
        private string m_encryptKeyID;

        private string m_expiredDate;
        //private string m_password;
        private string m_lastOpenDate;
        private int m_isValid;
        private long m_openLimit;
        private long m_openCounter;

        public int HeaderLength
        {
            get { return this.m_HeaderLength; }
        }

        public int HeaderVersion
        {
            get { return this.m_HeaderVersion; }
            set { this.m_HeaderVersion = value; }
        }
        public string FileID
        {
            get { return this.m_fileID; }
            set { this.m_fileID = value; }
        }
        public long FileLength
        {
            get { return this.m_fileLength; }
            set { this.m_fileLength = value; }
        }
        public int FileType
        {
            get { return this.m_fileType; }
            set { this.m_fileType = value; }
        }
        public int EncryptAlgorithm
        {
            get { return this.m_encryptAlgorithm; }
            set { this.m_encryptAlgorithm = value; }
        }
        public string EncryptKeyID
        {
            get { return this.m_encryptKeyID; }
            set { this.m_encryptKeyID = value; }
        }

        public string ExpiredDate
        {
            get { return this.m_expiredDate; }
            set { this.m_expiredDate = value; }
        }

        public string LastOpenDate
        {
            get { return this.m_lastOpenDate; }
            set { this.m_lastOpenDate = value; }
        }

        public int IsValid
        {
            get { return this.m_isValid; }
            set { this.m_isValid = value; }
        }

        public long OpenLimit
        {
            get { return this.m_openLimit; }
            set { this.m_openLimit = value; }
        }

        public long OpenCounter
        {
            get { return this.m_openCounter; }
            set { this.m_openCounter = value; }
        }

        public FileHeader()
        {
            this.m_HeaderVersion = 0;
            this.m_fileID = "";
            this.m_fileLength = 0;
            this.m_fileType = 0;
            this.m_encryptAlgorithm = 0;
            this.m_encryptKeyID = null;
            this.m_isValid = 1;
            this.m_expiredDate = string.Empty;
            this.m_lastOpenDate = string.Empty;
            this.m_openLimit = -1;
            this.m_openCounter = 0;
        }

        public bool ReadHeader(string filePath)
        {
            try
            {
                using (FileStream fileOp = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    // Check Header
                    byte[] checkHeader = new byte[5]; // 1 byte: Header Version, 4 bytes: End Identifier
                    if (fileOp.Length - (long)checkHeader.Length < 0) // 避免小於0的錯誤
                    {
                        checkHeader = null;
                        return false;
                    }

                    fileOp.Position = fileOp.Length - (long)checkHeader.Length; // 須避免小於0(上面處理過了)
                    fileOp.Read(checkHeader, 0, checkHeader.Length);

                    string endIdentifier = Encoding.UTF8.GetString(checkHeader, 1, m_endIdentifier.Length); // 4 bytes
                    if (endIdentifier != m_endIdentifier)
                    {
                        checkHeader = null;
                        return false;
                    }

                    // Set Header
                    this.m_HeaderVersion = checkHeader[0]; // 1 byte
                    switch (this.m_HeaderVersion)
                    {
                        case 0:
                            int headerLength = this.m_HeaderLength;
                            byte[] v0Header = new byte[headerLength];

                            fileOp.Position = (fileOp.Length - (long)headerLength) > 0 ? (fileOp.Length - (long)headerLength) : 0; // 須避免小於0
                            fileOp.Read(v0Header, 0, headerLength);

                            string startIdentifier = Encoding.UTF8.GetString(v0Header, 0, m_startIdentifier.Length); // 4 bytes
                            if (startIdentifier != m_startIdentifier)
                            {
                                checkHeader = null;
                                v0Header = null;
                                Util.log.Error(filePath + "  Read header failed.");
                                return false;
                            }

                            this.m_fileID = Encoding.UTF8.GetString(v0Header, 4, 16).Replace("\0", ""); // 16 bytes
                            this.m_fileLength = BitConverter.ToInt64(v0Header, 20); // 8 bytes
                            this.m_fileType = v0Header[28]; // 1 byte
                            this.m_encryptAlgorithm = v0Header[29]; // 1 byte
                            this.m_encryptKeyID = Encoding.UTF8.GetString(v0Header, 30, 16).Replace("\0", ""); // 16 bytes
                            this.m_isValid = v0Header[46];
                            this.ExpiredDate = Encoding.UTF8.GetString(v0Header, 47, 19).Replace("\0", ""); // 19 bytes
                            this.LastOpenDate = Encoding.UTF8.GetString(v0Header, 66, 19).Replace("\0", ""); // 19 bytes
                            this.OpenCounter = BitConverter.ToInt64(v0Header, 85); // 8 bytes
                            this.OpenLimit = BitConverter.ToInt64(v0Header, 93); // 8 bytes

                            v0Header = null;
                            break;
                        default:
                            checkHeader = null;
                            Util.log.Error(filePath + " Header version does not exist.");
                            return false;
                    } // end of switch
                    checkHeader = null;

                } // end of using
            }
            catch (Exception ex)
            {
                Util.log.Error("open " + filePath + " Exception\r\n" + ex.ToString());
                return false;
            }

            return true;
        }



        public bool WriteHeader(string filePath, bool rewrite)
        {
            try
            {
                this.m_HeaderVersion = 0;
                switch (this.m_HeaderVersion)
                {
                    case 0:
                        int headerLength = this.m_HeaderLength;
                        byte[] v0Header = new byte[headerLength];

                        Encoding.UTF8.GetBytes(m_startIdentifier, 0, m_startIdentifier.Length, v0Header, 0); // 4 bytes
                        Encoding.UTF8.GetBytes(this.m_fileID, 0, (this.m_fileID.Length < 16 ? this.m_fileID.Length : 16), v0Header, 4); // 16 bytes
                        byte[] lengthBuff = BitConverter.GetBytes(this.m_fileLength); // 8 bytes                   
                        Buffer.BlockCopy(lengthBuff, 0, v0Header, 20, 8);
                        v0Header[28] = Convert.ToByte(this.m_fileType); // 1 byte
                        v0Header[29] = Convert.ToByte(this.m_encryptAlgorithm); // 1 byte
                        Encoding.UTF8.GetBytes(this.m_encryptKeyID, 0, (this.m_encryptKeyID.Length < 16 ? this.m_encryptKeyID.Length : 16), v0Header, 30); // 16 bytes
                        v0Header[46] = Convert.ToByte(this.m_isValid);
                        Encoding.UTF8.GetBytes(this.ExpiredDate, 0, (this.ExpiredDate.Length < 19 ? this.ExpiredDate.Length : 19), v0Header, 47); // 19 bytes
                        Encoding.UTF8.GetBytes(this.LastOpenDate, 0, (this.LastOpenDate.Length < 19 ? this.LastOpenDate.Length : 19), v0Header, 66); // 19 bytes

                        lengthBuff = BitConverter.GetBytes(this.OpenCounter); // 8 bytes    
                        Buffer.BlockCopy(lengthBuff, 0, v0Header, 85, 8);
                        lengthBuff = BitConverter.GetBytes(this.OpenLimit); // 8 bytes    
                        Buffer.BlockCopy(lengthBuff, 0, v0Header, 93, 8);

                        v0Header[101] = Convert.ToByte(this.m_HeaderVersion); // 1 byte
                        Encoding.UTF8.GetBytes(m_endIdentifier, 0, m_endIdentifier.Length, v0Header, 102); // 4 bytes

                        //using (FileStream fileStream = AlphaFS.File.Open(filePath, FileMode.Append, FileAccess.Write)) // AlphaFS bug #168: File.Open + FileMode.Append = IOException: (87) 參數錯誤
                        using (FileStream fileOp = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Write)) // 改用FileMode.OpenOrCreate + Seek to end
                        {
                            if (rewrite)
                            {
                                fileOp.Seek(headerLength*(-1), SeekOrigin.End);
                                fileOp.Write(v0Header, 0, v0Header.Length);
                            }
                            else
                            {
                                fileOp.Seek(0, SeekOrigin.End);
                                fileOp.Write(v0Header, 0, v0Header.Length);
                            }                            
                        }

                        v0Header = null;
                        break;
                } // end of switch
            }
            catch (Exception ex)
            {
                Util.log.Error(ex.ToString());
                return false;
            }

            return true;
        }

        public bool AddHeader(string filePath, string expiredDate, int openLimit)
        {
            this.m_HeaderVersion = 0;
            switch (this.m_HeaderVersion)
            {
                case 0:
                    this.m_fileID = "";
                    this.m_fileType = 1;
                    this.m_encryptAlgorithm = 1;
                    this.m_isValid = 1;
                    this.m_expiredDate = expiredDate;
                    this.m_lastOpenDate = string.Empty;
                    this.OpenLimit = openLimit;
                    this.OpenCounter = 0;
                    this.m_encryptKeyID = "DMS_PDF"; // 取得快取中的密鑰ID
                    if (File.Exists(filePath))
                    {
                        this.m_fileLength = File.ReadAllBytes(filePath).Length;
                    }
                    else
                    {
                        this.m_fileLength = 0;
                    }
                    break;
            }

            return true;
        }
    }

    public class FileCache
    {
        private static readonly object EncryptKeyInfoLock = new object();

        private static int fileBlockSize = 16; // 64/256 * 1024; // AES加解密分塊大小


        public static bool ByteIsnotNull(byte[] checkBuffer)
        {
            for (int i = 0; i < checkBuffer.Length; i++)
            {
                if (checkBuffer[i] > 0)
                    return true;
            }
            return false;
        }

        public static byte[] GetByte(byte[] tInput, int index, int count)
        {
            try
            {
                byte[] anotherBytes;

                if ((index == 0) && (count == 0))
                    return tInput;
                if (index > tInput.Length)
                    return null;

                if (count > tInput.Length - index)
                    count = tInput.Length - index;

                anotherBytes = new byte[count];
                Buffer.BlockCopy(tInput, index, anotherBytes, 0, count);
                return anotherBytes;
            }
            catch (Exception ex)
            {
                Util.log.Error(ex.ToString());
                return null;
            }
        }

        // 讀取密文檔案片段
        public static int ReadEncryptedFile(string filePath, ref byte[] readBuffer, int length, long offset)
        {
            // 讀取Header
            FileHeader fileHeader = new FileHeader();
            if (fileHeader.ReadHeader(filePath) == false)
            {
                fileHeader = null;
                Util.log.Error(filePath + " Read header failed.");
                return -1;
            }

            long fileLength = fileHeader.FileLength; // 檔案明文長度
            string headerKeyID = fileHeader.EncryptKeyID;
            int headerLength = 0; // Header長度
            switch (fileHeader.HeaderVersion)
            {
                case 0:
                    headerLength = fileHeader.HeaderLength;
                    break;
            }
            fileHeader = null;

            // 計算需要讀取的分塊編號及數量
            int startPosition = (int)(offset % (long)fileBlockSize); // 此offset是對應到單一分塊中的哪個位置
            int startBlockNo = (int)(offset / (long)fileBlockSize); // 由第幾個分塊開始讀取，編號由0開始
            int readBlockCount = 0; // 需要讀取的分塊數量
            if (length > (fileBlockSize - startPosition)) // 若讀取長度大於offset所在分塊的剩餘空間
            {
                int alsoNeedLength = length - (fileBlockSize - startPosition); // 讀取長度扣除offset所在分塊的剩餘空間後，尚需要的長度
                readBlockCount = (alsoNeedLength / fileBlockSize) + 1; // 計算需完整讀取的分塊數量，後者是offset所在的分塊，至少會讀取該分塊，所以為1
                if (alsoNeedLength % fileBlockSize > 0) // 不足一分塊的剩餘長度再加1
                {
                    readBlockCount = readBlockCount + 1;
                }
            }
            else // 若讀取的檔案片段長度小於offset所在分塊的剩餘空間
            {
                readBlockCount = 1; // 需要讀取的分塊就只有offset所在的分塊
            }
            int totalBlockNumber = (fileLength % (long)fileBlockSize) > 0 ? (int)((fileLength / (long)fileBlockSize) + 1) : (int)(fileLength / (long)fileBlockSize); // 全檔案分塊數量

            // 讀取檔案至密文分塊
            object[] objArray = new object[1]; // 存放分塊的陣列
            try
            {
                using (FileStream fileOp = new FileStream(filePath, FileMode.Open, FileAccess.Read, System.IO.FileShare.Read))
                {
                    byte[] readBuffer_ = new byte[fileBlockSize * readBlockCount];
                    fileOp.Position = startBlockNo * fileBlockSize;

                    // 若此分塊包含有Header的部分會造成解密會錯，必須扣掉
                    int readLength = fileBlockSize * readBlockCount;
                    long noHeaderLength = (fileOp.Length - (long)headerLength) > 0 ? (fileOp.Length - (long)headerLength) : 0; // 避免小於0的錯誤
                    if (fileOp.Position + (long)readLength > noHeaderLength)
                    {
                        readLength = (int)(noHeaderLength - fileOp.Position) > 0 ? (int)(noHeaderLength - fileOp.Position) : 0; // 避免小於0的錯誤
                    }

                    fileOp.Read(readBuffer_, 0, readLength);
                    objArray[0] = readBuffer_;
                    readBuffer_ = null;
                }
            }
            catch (Exception ex)
            {
                objArray = null;
                Util.log.Error(ex.ToString());
                return -1;
            }

            // 取得加解密密鑰
            string encryptKey = CryptFunction.MD5(headerKeyID);
            byte[] MD5EncryptKey = Encoding.UTF8.GetBytes(encryptKey);

            // 解密密文分塊
            if (ByteIsnotNull((byte[])objArray[0]))
            {
                byte[] decryptBuffer = (byte[])objArray[0];
                objArray[0] = CryptFunction.AESDecrypt(decryptBuffer, MD5EncryptKey); // AES解密
                if (objArray[0] == null)
                {
                    objArray[0] = decryptBuffer;
                }
                decryptBuffer = null;
            }
            else
            {
                objArray[0] = new byte[fileBlockSize * readBlockCount];
            }

            // 合併明文分塊
            byte[] dst = new byte[readBlockCount * fileBlockSize];
            Buffer.BlockCopy((byte[])objArray[0], 0, dst, 0, ((byte[])objArray[0]).Length);

            // 取出檔案明文片段
            Buffer.BlockCopy(dst, startPosition, readBuffer, 0, length);

            objArray = null;
            dst = null;

            // 立即回收記憶體
            GC.Collect();
            GC.WaitForPendingFinalizers();

            return 0;
        }

        // 寫入密文檔案片段
        public static int WriteEncryptedFile(string filePath, byte[] writeBuffer, int length, long offset,string pwd, string expiredDate, int openLimit)
        {
            // 讀取Header
            FileHeader fileHeader = new FileHeader();
            if (fileHeader.ReadHeader(filePath) == false)
            {
                if (fileHeader.AddHeader(filePath, expiredDate, openLimit) == false)
                {
                    fileHeader = null;
                    Util.log.Error(filePath + " Add header failed.");
                    return -1;
                }
                fileHeader.FileID = pwd;
            }

            long fileLength = fileHeader.FileLength; // 檔案明文長度
            string headerKeyID = fileHeader.EncryptKeyID;
            int headerLength = 0;  // Header長度
            switch (fileHeader.HeaderVersion)
            {
                case 0:
                    headerLength = fileHeader.HeaderLength;
                    break;
            }

            // 計算需要寫入的分塊編號及數量
            int startPosition = (int)(offset % (long)fileBlockSize); // 此offset是對應到單一分塊中的哪個位置
            int startBlockNo = (int)(offset / (long)fileBlockSize); // 由第幾個分塊開始讀取，編號由0開始
            int readBlockCount = 0; // 需要寫入的分塊數量
            if (length > (fileBlockSize - startPosition)) // 若寫入長度大於offset所在分塊的剩餘空間
            {
                int alsoNeedLength = length - (fileBlockSize - startPosition); // 寫入長度扣除offset所在分塊的剩餘空間後，尚需要的長度
                readBlockCount = (alsoNeedLength / fileBlockSize) + 1; // 計算需完整寫入的分塊數量，後者是offset所在的分塊，至少會寫入該分塊，所以為1
                if (alsoNeedLength % fileBlockSize > 0) // 不足一分塊的剩餘長度再加1
                {
                    readBlockCount = readBlockCount + 1;
                }
            }
            else // 若寫入的檔案片段長度小於offset所在分塊的剩餘空間
            {
                readBlockCount = 1; // 需要寫入的分塊就只有offset所在的分塊
            }
            int totalBlockNumber = (fileLength % (long)fileBlockSize) > 0 ? (int)((fileLength / (long)fileBlockSize) + 1) : (int)(fileLength / (long)fileBlockSize); // 全檔案分塊數量

            // 讀取檔案至密文分塊
            object[] objArray = new object[1]; // 存放分塊的陣列
            try
            {
                using (FileStream fileOp = new FileStream(filePath, FileMode.Open, FileAccess.Read, System.IO.FileShare.Read))
                {
                    byte[] readBuffer = new byte[fileBlockSize * readBlockCount];
                    fileOp.Position = startBlockNo * fileBlockSize;

                    // 若此分塊包含有Header的部分會造成解密會錯，必須扣掉
                    int readLength = readBuffer.Length;
                    long noHeaderLength = (fileOp.Length - (long)headerLength) > 0 ? (fileOp.Length - (long)headerLength) : 0; // 避免小於0的錯誤
                    if (fileOp.Position + (long)readLength > noHeaderLength)
                    {
                        readLength = (int)(noHeaderLength - fileOp.Position) > 0 ? (int)(noHeaderLength - fileOp.Position) : 0; // 避免小於0的錯誤
                    }

                    fileOp.Read(readBuffer, 0, readLength);
                    objArray[0] = readBuffer;
                    readBuffer = null;
                }
            }
            catch (Exception ex)
            {
                fileHeader = null;
                objArray = null;
                Util.log.Error(ex.ToString());
                return -1;
            }

            // 取得加解密密鑰
            string encryptKey = CryptFunction.MD5(fileHeader.EncryptKeyID);
            byte[] MD5EncryptKey = Encoding.UTF8.GetBytes(encryptKey);

            // 解密密文分塊
            if (ByteIsnotNull((byte[])objArray[0]))
            {
                byte[] decryptBuffer = (byte[])objArray[0];
                objArray[0] = CryptFunction.AESDecrypt(decryptBuffer, MD5EncryptKey); // AES解密
                if (objArray[0] == null)
                {
                    objArray[0] = decryptBuffer;
                }
                decryptBuffer = null;
            }
            else
            {
                objArray[0] = new byte[fileBlockSize * readBlockCount];
            }

            // 合併明文分塊
            byte[] dst = new byte[readBlockCount * fileBlockSize];
            Buffer.BlockCopy((byte[])objArray[0], 0, dst, 0, ((byte[])objArray[0]).Length);

            // 寫入檔案明文片段
            Buffer.BlockCopy(writeBuffer, 0, dst, startPosition, length);

            // 加密明文分塊
            byte[] encryptBuffer = GetByte(dst, 0, dst.Length);
            if (ByteIsnotNull(encryptBuffer))
            {
                objArray[0] = CryptFunction.AESEncrypt(encryptBuffer, MD5EncryptKey); // AES加密
                if (objArray[0] == null)
                {
                    objArray[0] = encryptBuffer;
                }
            }
            else
            {
                objArray[0] = encryptBuffer;
            }
            encryptBuffer = null;
            dst = null;

            // 寫入密文分塊至檔案
            try
            {
                //Util.log.Debug("WriteEncryptedFile block size:" + fileBlockSize + ", file " + filePath);
                using (FileStream fileOp = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                {
                    fileOp.SetLength((fileOp.Length - (long)headerLength) > 0 ? (fileOp.Length - (long)headerLength) : 0); // 把Header從檔尾截掉
                    fileOp.Position = startBlockNo * fileBlockSize;
                    fileOp.Write((byte[])objArray[0], 0, ((byte[])objArray[0]).Length);
                }
            }
            catch (Exception ex)
            {
                fileHeader = null;
                objArray = null;
                Util.log.Error(ex.ToString());
                return -1;
            }
            objArray = null;

            // 更新Header記錄的明文長度
            long writeEndPosition = offset + length; // 寫入的明文檔案片段長度結尾的位置
            if (writeEndPosition > fileLength) // 若此次寫入的長度超出原記錄的長度，則更新
                fileHeader.FileLength = writeEndPosition;

            //fileHeader.OpenCounter++;
            //fileHeader.LastOpenDate = DateTime.Now.ToString("yyyyMMddHHmmss");
            // 寫入Header
            fileHeader.WriteHeader(filePath, false);
            fileHeader = null;

            // 立即回收記憶體
            GC.Collect();
            GC.WaitForPendingFinalizers();

            return 0;
        }

        public static bool IsLateToExpireDateTime(string expireDate)
        {
            try
            {
                if (string.IsNullOrEmpty(expireDate)) return false;
                if (DateTime.Compare(DateTime.Now, DateTime.Parse(expireDate)) > 0)
                    return true;
                else
                    return false;
            }
            catch { return true; }
        }

        public static bool IsLastOpenDateValid(string lastOpenDate)
        {
            try
            {
                if (string.IsNullOrEmpty(lastOpenDate)) return true;
                if (DateTime.Compare(DateTime.Now, DateTime.Parse(lastOpenDate)) > 0)
                    return true;
                else
                    return false;
            }
            catch { return true; }
        }
    }
}
