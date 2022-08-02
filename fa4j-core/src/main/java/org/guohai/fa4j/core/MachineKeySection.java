package org.guohai.fa4j.core;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * 模拟.net中的加密类
 * @author guohai
 */
public class MachineKeySection {


    /**
     * 3DES加密
     */
    private final String TRIPLEDES_KEY_ALGORITHM = "DESede";
    /**
     * 3DES填充
     */
    private final String TRIPLEDES_PADDING_PATTERN="DESede/CBC/PKCS5Padding";

    private final String DES_KEY_ALGORITHM = "DES";

    private final String DES_PADDING_PATTERN="DES/CBC/PKCS5Padding";

    private final String AES_KEY_ALGORITHM = "AES";

    private final String AES_PADDING_PATTERN="AES/CBC/PKCS5Padding";

    /**
     * 加密的KEY
     */
    private Key key;


    private final byte[] decryptionKeyBlob;


    private Cipher cipher;

    private IvParameterSpec ivP;

    public  MachineKeySection(String decryptionKey, DecryptionEnum decryptionType) throws Exception {

        decryptionKeyBlob = CryptoUtil.hexToBinary(decryptionKey);
        configureEncryptionObject(decryptionType);
    }

    /**
     * 根据不同的指定加密 算法生成不同的key和cipher对象
     * @param decryption
     * @throws Exception
     */
    private void configureEncryptionObject(DecryptionEnum decryption) throws Exception{
        switch (decryption){
            case TRIPLEDES:
                key = SecretKeyFactory.getInstance(TRIPLEDES_KEY_ALGORITHM).generateSecret(new DESedeKeySpec(decryptionKeyBlob));
                cipher = Cipher.getInstance(TRIPLEDES_PADDING_PATTERN);
                ivP = new IvParameterSpec(HashProvider.randomByteArray(8));
                break;
            case DES:
                key = SecretKeyFactory.getInstance(DES_KEY_ALGORITHM).generateSecret(new DESKeySpec(decryptionKeyBlob));
                cipher = Cipher.getInstance(DES_PADDING_PATTERN);
                ivP = new IvParameterSpec(HashProvider.randomByteArray(8));
                break;
            case AES:
                key = new SecretKeySpec(decryptionKeyBlob, AES_KEY_ALGORITHM);
                cipher = Cipher.getInstance(AES_PADDING_PATTERN);
                ivP = new IvParameterSpec(HashProvider.randomByteArray(16));
                break;
            default:
                if(decryptionKeyBlob.length == 8){
                    key = SecretKeyFactory.getInstance(DES_KEY_ALGORITHM).generateSecret(new DESKeySpec(decryptionKeyBlob));
                    cipher = Cipher.getInstance(DES_PADDING_PATTERN);
                    ivP = new IvParameterSpec(HashProvider.randomByteArray(8));
                }else {
                    key = new SecretKeySpec(decryptionKeyBlob, AES_KEY_ALGORITHM);
                    cipher = Cipher.getInstance(AES_PADDING_PATTERN);
                    ivP = new IvParameterSpec(HashProvider.randomByteArray(16));
                }
                break;

        }
    }

    /**
     * 对数据块进行加解密操作，目前仅运行加密
     * @param fEncrypt true 加密，flase 解密
     * @param buf 待加工的数据
     * @return 结果
     * @throws Exception 异常
     */
    public byte[] encryptOrDecryptData(boolean fEncrypt, byte[] buf) throws Exception {
        if (buf == null)
        {
            return null;
        }

        if(fEncrypt){
            // 加密
            byte[] ivHash = HashProvider.getIvHash(buf, roundupNumBitsToNumBytes(decryptionKeyBlob.length*8));
            byte[] tempBuf = new byte[buf.length+ ivHash.length];
            System.arraycopy(ivHash,0,tempBuf,0,ivHash.length);
            System.arraycopy(buf,0, tempBuf,ivHash.length,buf.length);
            cipher.init(Cipher.ENCRYPT_MODE,key, ivP);
            return cipher.doFinal(tempBuf);
        }
        else {
            // 解密

            cipher.init(Cipher.DECRYPT_MODE, key, ivP);
            byte[] a = cipher.getIV();
            buf = cipher.doFinal(buf);
            int ivLength = roundupNumBitsToNumBytes(decryptionKeyBlob.length*8);
            byte[] tempBuf = new byte[buf.length-ivLength];
            System.arraycopy(buf,ivLength, tempBuf,0,buf.length-ivLength);
            return tempBuf;
        }

    }

    /**
     * 根据key的大小 计算 原始的补填数据量
     * @param numBits
     * @return
     */
    private int roundupNumBitsToNumBytes(int numBits)
    {
        if (numBits < 0) {
            return 0;
        }
        return (numBits / 8) + (((numBits & 7) != 0) ? 1 : 0);
    }
}
