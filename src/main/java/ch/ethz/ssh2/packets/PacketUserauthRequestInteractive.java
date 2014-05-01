/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketUserauthRequestInteractive {

    private final byte[] payload;

    public PacketUserauthRequestInteractive(String serviceName, String user, String[] submethods) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
        tw.writeString(user);
        tw.writeString(serviceName);
        tw.writeString("keyboard-interactive");
        tw.writeString(""); // draft-ietf-secsh-newmodes-04.txt says that
        // the language tag should be empty.
        tw.writeNameList(null == submethods ? new String[]{} : submethods);
        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
