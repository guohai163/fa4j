package org.guohai.fa4j.core;

import org.junit.Assert;
import org.junit.Test;

import java.util.Date;

/**
 * 小于 4.0 版本的串行方案
 * @author guohai
 */
public class OldSerializeTests {

    /**
     * 测试用票据
     */
    FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1,"userName", new Date(), new Date(), true, "userData", "/" );

    /**
     * 串行方案
     */
    private static final boolean SERIALIZE = true;

    /**
     * 测试aes加密 和sha1 hash
     * @throws Exception
     */
    @Test
    public void testAesAndSha1() throws Exception {
        String encryptKey = "08347853AC82432810FCFEE731314D6FD1A692AAF3F554B9";
        String validationKey = "06681DC23D3B0AEBF340A8E1C493C37C8599BFFCA55849FF51C4ED158D45CB483D776848E339A12044CF0FA70C567AF781140806F327A3EEA17311EE5599FE3B";

        String dotnetSecretMsg = "437D81F4E6004425962C5ADE51E5F47A2B1BB0642CE7F3EF6813BD9CC3C76874855CD6F3DE1251559AE8932F8F4C98291A076AED3CDF0023960B8DA2B8A33FB38E184206604A0F05B8F05AA9F2D8229882A5EFB694918BB58A7CB03CA23755E6A633B0A413A912E20BDC0A0D11EF21C4E9D44BD55A16AB7A69EEB90F6393DBFC41983E91";



        HashProvider hashProvider = new HashProvider(validationKey);
        MachineKeySection machineKeySection = new MachineKeySection(encryptKey, DecryptionEnum.AES);

        FormsAuthentication formsAuthentication = new FormsAuthentication(machineKeySection, hashProvider, SERIALIZE);

        FormsAuthenticationTicket dotnetTicket = formsAuthentication.decrypt(dotnetSecretMsg);
        Assert.assertNotNull(dotnetTicket);
        String cooke = formsAuthentication.encrypt(ticket);
        FormsAuthenticationTicket newTicket = formsAuthentication.decrypt(cooke);
        Assert.assertEquals(ticket.getUserData(), newTicket.getUserData());
    }

    /**
     * 测试des加密 和sha1 hash
     * @throws Exception
     */
    @Test
    public void testDesAndSha1() throws Exception{
        String encryptKey = "08347853AC82432810FCFEE731314D6FD1A692AAF3F554B9";
        String validationKey = "06681DC23D3B0AEBF340A8E1C493C37C8599BFFCA55849FF51C4ED158D45CB483D776848E339A12044CF0FA70C567AF781140806F327A3EEA17311EE5599FE3B";

        String dotnetSecretMsg = "63C10D121CA388AA7C99F51880C25B91F3DE20266CA6BE2F96AF52204EF9122F0283192C411B6958A07242294CEF98E501C7D572B810992DBBC880A8A5F5351364ED625031D5DEA33461623C916CB7822AE2EC506140F3C94538C2C7EFD3CF0CFF9AFA5A9945E34F437BE9905F87817CECAC5ED7";



        HashProvider hashProvider = new HashProvider(validationKey);
        MachineKeySection machineKeySection = new MachineKeySection(encryptKey, DecryptionEnum.DES);

        FormsAuthentication formsAuthentication = new FormsAuthentication(machineKeySection, hashProvider, SERIALIZE);

        FormsAuthenticationTicket dotnetTicket = formsAuthentication.decrypt(dotnetSecretMsg);
        Assert.assertNotNull(dotnetTicket);
        String cooke = formsAuthentication.encrypt(ticket);
        FormsAuthenticationTicket newTicket = formsAuthentication.decrypt(cooke);
        Assert.assertEquals(ticket.getUserData(), newTicket.getUserData());
    }

    /**
     * 测试3des加密 和sha1 hash
     * @throws Exception
     */
    @Test
    public void testTripleDesAndSha1() throws Exception{
        String encryptKey = "08347853AC82432810FCFEE731314D6FD1A692AAF3F554B9";
        String validationKey = "06681DC23D3B0AEBF340A8E1C493C37C8599BFFCA55849FF51C4ED158D45CB483D776848E339A12044CF0FA70C567AF781140806F327A3EEA17311EE5599FE3B";

        String dotnetSecretMsg = "2076103AEC5AA86E6187063FE758530059FD0B49F8A4DB3879FE692052575B0FF112A5D57BBDC8C320C28307B056C666C04E8608088062DE6F5E21579F587F597D987B71C9474A1179F36C63A3140794D0C5DC1461A9B54D6A16C0865D6ADEF22DA94A03E266E774D059BE8DDCEC98910D24B5B7C49D911FA9E5D34071D88EDDD4AD79A5";



        HashProvider hashProvider = new HashProvider(validationKey);
        MachineKeySection machineKeySection = new MachineKeySection(encryptKey, DecryptionEnum.TRIPLEDES);

        FormsAuthentication formsAuthentication = new FormsAuthentication(machineKeySection, hashProvider, SERIALIZE);

        FormsAuthenticationTicket dotnetTicket = formsAuthentication.decrypt(dotnetSecretMsg);
        Assert.assertNotNull(dotnetTicket);
        String cooke = formsAuthentication.encrypt(ticket);
        FormsAuthenticationTicket newTicket = formsAuthentication.decrypt(cooke);
        Assert.assertEquals(ticket.getUserData(), newTicket.getUserData());
    }
}
