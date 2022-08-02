package org.guohai.fa4j.core;

import org.junit.Assert;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class FaTests {

    FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1,"userName", new Date(), new Date(), true, "userData", "/" );

    @Test
    public void testAESAndSha1Unsafe() throws Exception {

        String encryptKey = "08347853AC82432810FCFEE731314D6FD1A692AAF3F554B9";
        String validationKey = "06681DC23D3B0AEBF340A8E1C493C37C8599BFFCA55849FF51C4ED158D45CB483D776848E339A12044CF0FA70C567AF781140806F327A3EEA17311EE5599FE3B";

        HashProvider hashProvider = new HashProvider(validationKey);
        MachineKeySection machineKeySection = new MachineKeySection(encryptKey, DecryptionEnum.AES);

        FormsAuthentication formsAuthentication = new FormsAuthentication(machineKeySection, hashProvider, true);
        String cooke = formsAuthentication.encrypt(ticket);
        FormsAuthenticationTicket newTicket = formsAuthentication.decrypt(cooke);
        Assert.assertEquals(ticket.getUserData(), newTicket.getUserData());
    }

    @Test
    public void testAESAndSha1Safe()  throws Exception {
        String encryptKey = "08347853AC82432810FCFEE731314D6FD1A692AAF3F554B9";
        String validationKey = "06681DC23D3B0AEBF340A8E1C493C37C8599BFFCA55849FF51C4ED158D45CB483D776848E339A12044CF0FA70C567AF781140806F327A3EEA17311EE5599FE3B";

        HashProvider hashProvider = new HashProvider(validationKey);
        MachineKeySection machineKeySection = new MachineKeySection(encryptKey, DecryptionEnum.AES);

        FormsAuthentication formsAuthentication = new FormsAuthentication(machineKeySection, hashProvider, false);
        String cooke = formsAuthentication.encrypt(ticket);
        FormsAuthenticationTicket newTicket = formsAuthentication.decrypt(cooke);
        Assert.assertEquals(ticket.getUserData(), newTicket.getUserData());
    }
    @Test
    public void test3DESAndSha1Unsafe() throws Exception {
        String encryptKey = "115CEC1CBD362BB7178FB9491E86AEF1C4EE5DCED77FBB72";
        String validationKey = "9DAD6CBD155D05BB25B5909D858B183C999E39A4EF3CC4A89E10822B990E3602C071BED55DA74D097D1314E1291A547CCBADA1A6BB54F46D25E50D035FE978F5";

        HashProvider hashProvider = new HashProvider(validationKey);
        MachineKeySection machineKeySection = new MachineKeySection(encryptKey, DecryptionEnum.TRIPLEDES);

        FormsAuthentication formsAuthentication = new FormsAuthentication(machineKeySection, hashProvider, true);
        String cooke = formsAuthentication.encrypt(ticket);
        FormsAuthenticationTicket newTicket = formsAuthentication.decrypt(cooke);
        Assert.assertEquals(ticket.getUserData(), newTicket.getUserData());
    }
}
