package org.guohai.fa4j.core;

/**
 * 模拟实现 .net System.Web.Security.Cryptography 下的 CryptoUtil类
 * @author guohai
 */
public class CryptoUtil {

    /**
     * 适用于FA中 KEY转为 byte数组
     * @param data 字符串格式 的KEY
     * @return 转换成功的KEY
     */
    public static byte[] hexToBinary(String data){
        if (data == null || data.length() % 2 != 0)
        {
            // input string length is not evenly divisible by 2
            return null;
        }

        byte[] binary = new byte[data.length() / 2];

        for (int i = 0; i < binary.length; i++)
        {
            int highNibble = HexToInt(data.charAt(2 * i));
            int lowNibble = HexToInt(data.charAt(2 * i + 1));

            if (highNibble == -1 || lowNibble == -1)
            {
                return null; // bad hex data
            }
            binary[i] = (byte)((highNibble << 4) | lowNibble);
        }

        return binary;
    }

    /**
     * byte转换为string方便传输
     * c#中byte是0~255  java中byte是-128~127小心此坑
     * @param data
     * @return
     */
    public static String binaryToHex(byte[] data){
        if (data == null)
        {
            return null;
        }

        char[] hex = new char[data.length * 2];

        for (int i = 0; i < data.length; i++)
        {
            short thisByte = (short) (data[i] & 0x0FF);

            hex[2 * i] = NibbleToHex((short)(thisByte >> 4)); // high nibble
            hex[2 * i + 1] = NibbleToHex((short)(thisByte & 0xf)); // low nibble
        }

        return new String(hex);
    }

    /**
     * 编码时使用，
     * @param nibble
     * @return
     */
    private static char NibbleToHex(short nibble)
    {
        return (char)((nibble < 10) ? (nibble + '0') : (nibble - 10 + 'A'));
    }


    /**
     * 解码时使用
     * @param h
     * @return
     */
    private static int HexToInt(char h)
    {
        return (h >= '0' && h <= '9') ? h - '0' :
                (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
                        (h >= 'A' && h <= 'F') ? h - 'A' + 10 :
                                -1;
    }
}
