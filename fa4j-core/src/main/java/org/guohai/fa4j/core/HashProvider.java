package org.guohai.fa4j.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

/**
 * 负责对加密数据进行 hash处理，目前支持sha1算法
 * @author guohai
 */
public class HashProvider {


    /**
     * .net 中的业务
     *         private const int MD5_KEY_SIZE          = 64;
     *         private const int MD5_HASH_SIZE         = 16;
     *
     *         private const int SHA1_KEY_SIZE         = 64;
     *         private const int HMACSHA256_KEY_SIZE       = 64;
     *         private const int HMACSHA384_KEY_SIZE       = 128;
     *         private const int HMACSHA512_KEY_SIZE       = 128;
     *         private const int SHA1_HASH_SIZE        = 20;
     *         private const int HMACSHA256_HASH_SIZE      = 32;
     *         private const int HMACSHA384_HASH_SIZE      = 48;
     *         private const int HMACSHA512_HASH_SIZE      = 64;
     */


    private int hashSize;
    private String algorithmName ;
//    private int autoGenValidationKeySize;

    private final Mac mac;

    private final HashTypeEnum hashTypeEnum;
    /**
     * 密钥转为byte的存储
     */
    private final byte[] validationKeyBlob;

    /**
     * 构造方法，负责初始化 Mac对象，。调用 此方法使用sha1进行hash
     * @param validationKey hash的key
     * @throws NoSuchAlgorithmException 生成密钥时，如果指定了错误的参数会抛
     * @throws InvalidKeyException 初始化时如果KEY有错误会抛出
     */
    public HashProvider(String validationKey) throws NoSuchAlgorithmException, InvalidKeyException {
        this(validationKey, HashTypeEnum.SHA1);
    }
    
    /**
     * 构造方法，负责初始化 Mac对象，
     * @param validationKey hash的key
     * @param typeEnum hash算法
     * @throws NoSuchAlgorithmException 生成密钥时，如果指定了错误的参数会抛
     * @throws InvalidKeyException 初始化时如果KEY有错误会抛出
     */
    public HashProvider(String validationKey, HashTypeEnum typeEnum) throws NoSuchAlgorithmException, InvalidKeyException {

        this.hashTypeEnum = typeEnum;
        validationKeyBlob = CryptoUtil.hexToBinary(validationKey);
        initHashSize(typeEnum);

        SecretKeySpec signinKey = new SecretKeySpec(validationKeyBlob, algorithmName);
        //生成一个指定 Mac 算法 的 Mac 对象
        mac = Mac.getInstance(algorithmName);
        //用给定密钥初始化 Mac 对象
        mac.init(signinKey);
    }

    private void initHashSize(HashTypeEnum typeEnum){
        switch (typeEnum){
            case MD5:
                hashSize = 16;
                algorithmName = "HmacMD5";
                break;
            case SHA1:
                hashSize = 20;
                algorithmName = "HmacSHA1";
                break;
            case SHA256:
                hashSize = 32;
                algorithmName = "HmacSHA256";
                break;
            case SHA384:
                hashSize = 48;
                algorithmName = "HmacSHA384";
                break;
            case SHA512:
                hashSize = 64;
                algorithmName = "HmacSHA512";
                break;
        }
    }

    /**
     * 生成指定长度的随机 byte 数组
     * @param length 指定生成的长度
     * @return 生成的结果
     */
    public static byte[] randomByteArray(int length){
        byte[] arr = new byte[length];
        new Random().nextBytes(arr);
        return arr;
    }


    /**
     * 对BUF 按指定hash算法计算摘要值
     * @param buf 待处理字符串
     * @return hash后结果
     */
    public byte[] getHMACSHAHash(byte[] buf) throws NoSuchAlgorithmException {
        return this.hashTypeEnum == HashTypeEnum.MD5 ? hashDataUsingNonKeyedAlgorithm(buf) :mac.doFinal(buf);
    }

    /**
     * 无key的hash ，此处特指md5
     * @param buf 待处理的数据
     * @return hash后的结果串
     */
    public byte[] hashDataUsingNonKeyedAlgorithm(byte[] buf) throws NoSuchAlgorithmException {
        byte[] tmpBuf = new byte[buf.length+validationKeyBlob.length];
        System.arraycopy(buf,0, tmpBuf,0,buf.length);
        System.arraycopy(validationKeyBlob, 0, tmpBuf, buf.length, validationKeyBlob.length);

        return MessageDigest.getInstance("MD5").digest(tmpBuf);
    }

    /**
     * 检查并移除hash值
     * @param bufHashed 待处理的数据
     * @return 移除后的结果
     * @throws Exception 异常
     */
    public byte[] checkHashAndRemove(byte[] bufHashed) throws Exception {
        byte[] originalData = new byte[bufHashed.length-hashSize];
        byte[] originalHash = new byte[hashSize];
        System.arraycopy(bufHashed,bufHashed.length-hashSize, originalHash,0, hashSize);
        System.arraycopy(bufHashed,0, originalData,0, bufHashed.length-hashSize);
        if(checkHash(originalData,originalHash)){
            return originalData;
        }else{
            return null;
        }
    }

    /**
     * 检查hash值是否正确
     * @param originalData 数据体
     * @param originalHash 原始的hash
     * @return 检查的成功性
     * @throws Exception 抛出的异常
     */
    public boolean checkHash(byte[] originalData, byte[] originalHash) throws Exception {
        byte[] hashCheckBlob  = getHMACSHAHash(originalData);
        if(hashCheckBlob == null){
            throw new Exception("Hash is not appended to the end");
        }
        if(hashCheckBlob.length != hashSize){
            throw new Exception("Hash size length expected");
        }

        return Arrays.equals(hashCheckBlob, originalHash);
    }
}
