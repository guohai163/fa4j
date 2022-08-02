package org.guohai.fa4j.spring.boot;


import org.guohai.fa4j.core.FormsAuthentication;
import org.guohai.fa4j.core.FormsAuthenticationTicket;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.Assert;

import java.util.Date;

@SpringBootTest(classes = {org.guohai.fa4j.spring.boot.FaConfiguration.class})
@TestPropertySource("classpath:aes.properties")
public class FaAesStarterTests {
    @Autowired
    FormsAuthentication formsAuthentication;

    FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1,"userName", new Date(), new Date(), true, "userData", "/" );

    @Test
    public void testAesFA(){


        try {
            String en = formsAuthentication.encrypt(ticket);
            FormsAuthenticationTicket newTicket = formsAuthentication.decrypt(en);
            Assert.isTrue(ticket.getUserData().equals(newTicket.getUserData()));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
