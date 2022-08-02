package org.guohai.fa4j.core;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 代替.net 的System.Web.Security 名称空间下同名类
 * 主要实现.net 2 ~ 4.5的加密算法
 */

public class FormsAuthentication {

    private static final Logger log = LoggerFactory.getLogger(FormsAuthentication.class);

    /**
     * 支持的最大票据长度
     */
    private final int MAX_TICKET_LENGTH = 4096;
    /**
     * hash
     */
    private final HashProvider hashProvider;
    /**
     * 加密
     */
    private final MachineKeySection machineKeySection;

    /**
     * 是否使用高版本的安全串行化
     * true使用不安全版本
     * false使用安全版本，默认值
     */
    private boolean useLegacyFormsAuthenticationTicketCompatibility = false;

    /**
     * 构造方法，需要传入两个 参数
     *
     * @param machineKeySection                               加密用对象
     * @param hashProvider                                    hash用对象
     * @param useLegacyFormsAuthenticationTicketCompatibility 是否使用高版本的安全串行化, false使用安全版本，默认值
     */
    public FormsAuthentication(MachineKeySection machineKeySection, HashProvider hashProvider, boolean useLegacyFormsAuthenticationTicketCompatibility) {
        if (null == machineKeySection || null == hashProvider) {
            throw new NullPointerException("input machineKeySection or hashProvider is null");
        }
        this.hashProvider = hashProvider;
        this.machineKeySection = machineKeySection;
        this.useLegacyFormsAuthenticationTicketCompatibility = useLegacyFormsAuthenticationTicketCompatibility;
    }

    /**
     * 目前支持 3DES、DES、AES加密和 SHA1的HASH。
     * @param ticket 待加密的对象
     * @return 加密后再次编码的字符串
     * @throws Exception 异常
     */
    public String encrypt(FormsAuthenticationTicket ticket) throws Exception {
        if(ticket == null){
            throw new NullPointerException("ticket is null");
        }

        byte[] bBlob;
        // 通过安全级别参数，判断串行方案
        if(useLegacyFormsAuthenticationTicketCompatibility){
            log.debug("user {} use unsafe serialize", ticket.getName());
            bBlob = UnsafeFaTicketSerializer.cookieAuthConstructTicket(ticket);
        }else {
            bBlob = FormsAuthenticationTicketSerializer.serialize(ticket);
        }

        //串行出错
        if(bBlob == null){
            log.error("name {} serialize fail", ticket.getName());
            return null;
        }

        // 获取需要填充的数据
        byte[] hashBlob = this.hashProvider.getHMACSHAHash(bBlob);
        if (hashBlob == null)
        {
            log.error("name {} get iv hash fail", ticket.getName());
            return null;
        }
        byte[]  cookieBlob = new byte[hashBlob.length + bBlob.length];
        System.arraycopy(bBlob,0,cookieBlob, 0, bBlob.length);
        System.arraycopy(hashBlob, 0, cookieBlob, bBlob.length, hashBlob.length);

        //加密数据
        byte[] encryptedCookieBlob = machineKeySection.encryptOrDecryptData(true, cookieBlob);

        if (encryptedCookieBlob == null)
        {
            log.error("name {} encrypt fail", ticket.getName());
            return null;
        }

        hashBlob = hashProvider.getHMACSHAHash(encryptedCookieBlob);
        cookieBlob = new byte[hashBlob.length + encryptedCookieBlob.length];
        System.arraycopy(encryptedCookieBlob,0,cookieBlob, 0, encryptedCookieBlob.length);
        System.arraycopy(hashBlob, 0, cookieBlob, encryptedCookieBlob.length, hashBlob.length);

        return CryptoUtil.binaryToHex(cookieBlob);
    }

    /**
     * 对数据进行解密
     * @param data 解密的串
     * @return 解密后的对象
     * @throws Exception 异常
     */
    public FormsAuthenticationTicket decrypt(String data) throws Exception {
        if (null == data || data.length() > MAX_TICKET_LENGTH)
            throw new NullPointerException("in data is null");
        byte[] bBlob = null;
        if ((data.length() % 2) == 0){
            bBlob = CryptoUtil.hexToBinary(data);
        }
        if (bBlob == null || bBlob.length < 1) {
            log.error("cookies data to byte array fail");
            throw new IllegalArgumentException("encryptedTicket");
        }
        // 移除 hash部分
        bBlob = hashProvider.checkHashAndRemove(bBlob);
        byte[] decryptedCookie = machineKeySection.encryptOrDecryptData(false, bBlob);
        bBlob = hashProvider.checkHashAndRemove(decryptedCookie);
        if(bBlob != null){
            if(useLegacyFormsAuthenticationTicketCompatibility){

                return UnsafeFaTicketSerializer.cookieAuthByte(bBlob);
            }else {
                return FormsAuthenticationTicketSerializer.deserialize(bBlob);
            }

        }
        log.error("user cookies data Decrypt fail");
        return null;
    }
}

