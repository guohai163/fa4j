package org.guohai.fa4j.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

/**
 * 负责对加密数据进行 hash处理，目前支持sha1算法
 * @author guohai
 */
public class HashProvider {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final int HASH_SIZE = 20;

    private Mac mac;

    /**
     * 密钥转为byte的存储
     */
    private byte[] validationKeyBlob;
    /**
     * 构造方法，负责初始化 Mac对象，
     * @param validationKey hash的key
     * @throws NoSuchAlgorithmException 生成密钥时，如果指定了错误的参数会抛
     * @throws InvalidKeyException 初始化时如果KEY有错误会抛出
     */
    public HashProvider(String validationKey) throws NoSuchAlgorithmException, InvalidKeyException {


        validationKeyBlob = CryptoUtil.hexToBinary(validationKey);

        SecretKeySpec signinKey = new SecretKeySpec(validationKeyBlob, HMAC_SHA1_ALGORITHM);
        //生成一个指定 Mac 算法 的 Mac 对象
        mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        //用给定密钥初始化 Mac 对象
        mac.init(signinKey);
    }

    /**
     * 生成指定长度的随机 byte 数组
     * @param length
     * @return
     */
    public static byte[] randomByteArray(int length){
        byte[] arr = new byte[length];
        new Random().nextBytes(arr);
        return arr;
    }

    /**
     * 反复数据填充，填充内容为buf的头20个字节，原因不明
     * @param buf
     * @param ivLength
     * @return
     */
    public static byte[] getIvHash(byte[] buf, int ivLength){
        int bytesToWrite = ivLength;
        int bytesWritten = 0;
        byte[] iv = new byte[ivLength];
        byte[] hash = buf;
        while (bytesWritten < ivLength)
        {

            int bytesToCopy = Math.min(HASH_SIZE, bytesToWrite);
            System.arraycopy(hash, 0, iv, bytesWritten, bytesToCopy);

            bytesWritten += bytesToCopy;
            bytesToWrite -= bytesToCopy;
        }
        return iv;
    }

    /**
     * 对BUF 按指定hash算法计算摘要值
     * @param buf 待处理字符串
     * @return hash后结果
     */
    public byte[] getHMACSHAHash(byte[] buf) {

        return mac.doFinal(buf);
    }

    /**
     * 检查并移除hash值
     * @param bufHashed
     * @return
     */
    public byte[] checkHashAndRemove(byte[] bufHashed) throws Exception {
        byte[] originalData = new byte[bufHashed.length-HASH_SIZE];
        byte[] originalHash = new byte[HASH_SIZE];
        System.arraycopy(bufHashed,bufHashed.length-HASH_SIZE, originalHash,0, HASH_SIZE);
        System.arraycopy(bufHashed,0, originalData,0, bufHashed.length-HASH_SIZE);
        if(checkHash(originalData,originalHash)){
            return originalData;
        }else{
            return null;
        }
    }

    /**
     * 检查hash值是否正确
     * @param originalData
     * @param originalHash
     * @return
     * @throws Exception
     */
    public boolean checkHash(byte[] originalData, byte[] originalHash) throws Exception {
        byte[] hashCheckBlob  = getHMACSHAHash(originalData);
        if(hashCheckBlob == null){
            throw new Exception("Hash is not appended to the end");
        }
        if(hashCheckBlob.length != HASH_SIZE){
            throw new Exception("Hash size length expected");
        }

        return Arrays.equals(hashCheckBlob, originalHash);
    }
}
