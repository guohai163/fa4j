package org.guohai.fa4j.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import static org.guohai.fa4j.core.FormsAuthenticationTicketSerializer.bytesToLong;
import static org.guohai.fa4j.core.FormsAuthenticationTicketSerializer.longToBytes;

/**
 * 此类模拟 .net 2里不安全的串行化方案。
 * 原始代码在win2003系统携带的webengine.dll 文件中
 * 原始代码是基于CPP实现
 */
public class UnsafeFaTicketSerializer {
    /**
     * Current (v0) ticket format
     * ==========================
     * random byte: 8 bytes
     * FormsAuthenticationTicket.Version: 1 byte
     * FormsAuthenticationTicket.Name: 1+ bytes ( 0+ payload, 2 blank)
     * FormsAuthenticationTicket.IssueDateFileTime: 8 bytes
     * FormsAuthenticationTicket.IsPersistent: 1 byte
     * FormsAuthenticationTicket.ExpirationUtc: 8 bytes
     * FormsAuthenticationTicket.UserData: 1+ bytes ( 0+ payload, 2 blank)
     * FormsAuthenticationTicket.CookiePath: 1+ bytes ( 0+ payload, 2 blank)
     */

    /**
     * 起始留空位置，提高 安全性可以为随机byte
     */
    private static final int COOKIE_AUTH_TICKET_START = 8;
    public static byte[] cookieAuthConstructTicket(FormsAuthenticationTicket ticket) throws IOException {
        ByteArrayOutputStream ticketWriter = new ByteArrayOutputStream();
        // write 8 byte data
        ticketWriter.write(HashProvider.randomByteArray(COOKIE_AUTH_TICKET_START));
        // write 1B version
        ticketWriter.write((byte)ticket.getVersion());
        // write name
        ticketWriter.write(stringToBytes(ticket.getName()));
        // write Issue
        long issueTick = ticket.getIssueDateUtcTick();
        ticketWriter.write(longToBytes(ticket.getIssueDateUtcToFileTime()));
        // write IsPersistent
        ticketWriter.write(ticket.isPersistent()?0x01:0x00);
        // write expires
        ticketWriter.write(longToBytes(ticket.getExpirationUtcFileTime()));
        // write userdata
        ticketWriter.write(stringToBytes(ticket.getUserData()));
        // write path
        ticketWriter.write(stringToBytes(ticket.getCookiePath()));

        return ticketWriter.toByteArray();
    }

    public static FormsAuthenticationTicket cookieAuthByte(byte[] data){
        FormsAuthenticationTicket ticket = new FormsAuthenticationTicket();
        ByteBuffer buffer = ByteBuffer.wrap(data);
        byte[] timeLong = new byte[8];
        // 跳过随机的字符串
        buffer.get(timeLong);
        ticket.setVersion(buffer.get());

        ticket.setName(bytesToString(buffer));


        buffer.get(timeLong);
        ticket.setIssueDateUtcFileTime(bytesToLong(timeLong));

        ticket.setPersistent(buffer.get()==1);

        buffer.get(timeLong);
        ticket.setExpirationUtcFileTime(bytesToLong(timeLong));

        ticket.setUserData(bytesToString(buffer));

        ticket.setCookiePath(bytesToString(buffer));

        return ticket;
    }



    private static byte[] stringToBytes(String x){
        byte[] bytes = new byte[x.length() * 2+2];

        for(int i=0;i<x.length();i++){
            char c = x.charAt(i);
            bytes[2 * i] = (byte) c;
            bytes[2 * i + 1] = (byte) (c>> 8);

        }
        bytes[bytes.length-1] = 0;

        return bytes;
    }

    private static String bytesToString(ByteBuffer buffer){
        StringBuilder data = new StringBuilder();
        byte[] cw = new byte[2];
        while (true){
            buffer.get(cw);
            if(cw[0] ==0 && cw[1] == 0){
                break;
            }
            char c = (char) (cw[0]+(cw[1]<<8));
            data.append(c);
        }
        return data.toString();
    }

}
