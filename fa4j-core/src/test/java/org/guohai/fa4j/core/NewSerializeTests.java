package org.guohai.fa4j.core;

import org.junit.Assert;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

/**
 * 大于 4.0 版本的串行方案
 * @author guohai
 */
public class NewSerializeTests {

    /**
     * 测试用票据
     */
    FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1,"userName", new Date(), new Date(), true, "userData", "/" );

    /**
     * 串行方案
     */
    private static final boolean SERIALIZE = false;

    private static final String DECRYPTION_KEY = "08347853AC82432810FCFEE731314D6FD1A692AAF3F554B9";

    private static final String VALIDATION_KEY = "06681DC23D3B0AEBF340A8E1C493C37C8599BFFCA55849FF51C4ED158D45CB483D776848E339A12044CF0FA70C567AF781140806F327A3EEA17311EE5599FE3B";
    /**
     * 测试aes加密 和sha1 hash
     * @throws Exception
     */
    @Test
    public void testAesAndSha1() throws Exception {

        String dotnetSecretMsg = "8549CD8F5B991214E720112BAEFDE218DE597506C2C3575AFC1B0A60900C20548085F013B7B09E8C5584B1790135777CF323F7581A2CD7F67861B46098051329814129DEEF1CC49B6745C4D1F5934138FD32F7DE8B2C879574B958529788EA6BDD7711F8FEEFA5B6F77D2C0537E364E3462DB2796798D28867DE1FA854A93827AF74B578";



        HashProvider hashProvider = new HashProvider(VALIDATION_KEY);
        MachineKeySection machineKeySection = new MachineKeySection(DECRYPTION_KEY, DecryptionEnum.AES);

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

        String dotnetSecretMsg = "42E53E1E3D894EC930F0402D28E90225EEED506C3EFB1D50D29827E5F36DB6A4C088301ECB166F9CF2D3B70C9359A5CFA3DEFA80310C0DA75437189CD1FCCC624DC02343BF0412392AEA25E39CEEDFDE34C48E426C0D758081A892A4D64D95133876386ABE6E54A0AC3B0A39";



        HashProvider hashProvider = new HashProvider(validationKey);
        MachineKeySection machineKeySection = new MachineKeySection(encryptKey, DecryptionEnum.DES);

        FormsAuthentication formsAuthentication = new FormsAuthentication(machineKeySection, hashProvider, true);

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

        String dotnetSecretMsg = "B04D5C3FF426B8D034131CD07D62B9BF269E891DF9D5067DD2980123A275FD2321E8A68C0A8D45CDD07E35D6F1A8A7BE07450E95A01B77F6B05C5BA47FE370D987D02AA9E08731CA5EF70EEE142B7FE4BAF061EE705586A2BE48DCF5E40144AD9AD6F620203B38C1E1534E209CE7B5EA1396E6F5504BDF69FCA3FBE3";

        HashProvider hashProvider = new HashProvider(VALIDATION_KEY);
        MachineKeySection machineKeySection = new MachineKeySection(DECRYPTION_KEY, DecryptionEnum.TRIPLEDES);

        FormsAuthentication formsAuthentication = new FormsAuthentication(machineKeySection, hashProvider, SERIALIZE);

        FormsAuthenticationTicket dotnetTicket = formsAuthentication.decrypt(dotnetSecretMsg);
        Assert.assertNotNull(dotnetTicket);
        String cooke = formsAuthentication.encrypt(ticket);
        FormsAuthenticationTicket newTicket = formsAuthentication.decrypt(cooke);
        Assert.assertEquals(ticket.getUserData(), newTicket.getUserData());
    }
}
