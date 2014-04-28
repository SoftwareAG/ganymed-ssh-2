/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */

package ch.ethz.ssh2.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.OutputStream;

import ch.ethz.ssh2.util.StringEncoder;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public class ClientServerHello {
    private final String client_line;
    private final String server_line;

    private ClientServerHello(String client_line, String server_line) {
        this.client_line = client_line;
        this.server_line = server_line;
    }

    public static ClientServerHello clientHello(String softwareversion, InputStream bi, OutputStream bo)
            throws IOException {
        return exchange(softwareversion, bi, bo, true);
    }

    public static ClientServerHello serverHello(String softwareversion, InputStream bi, OutputStream bo)
            throws IOException {
        return exchange(softwareversion, bi, bo, false);
    }

    private static ClientServerHello exchange(String softwareversion, InputStream bi, OutputStream bo, boolean clientMode)
            throws IOException {
        String localIdentifier = String.format("SSH-2.0-%s", softwareversion);

        bo.write(StringEncoder.GetBytes(String.format("%s\r\n", localIdentifier)));
        bo.flush();

        // Expect SSH-protoversion-softwareversion SP comments CR LF
        String remoteIdentifier = new LineNumberReader(new InputStreamReader(bi)).readLine();
        if(null == remoteIdentifier) {
            throw new IOException("Premature connection close");
        }
        if(!remoteIdentifier.startsWith("SSH-")) {
            throw new IOException(String.format("Malformed SSH identification %s", remoteIdentifier));
        }
        if(!remoteIdentifier.startsWith("SSH-1.99-")
                && !remoteIdentifier.startsWith("SSH-2.0-")) {
            throw new IOException(String.format("Incompatible remote protocol version %s", remoteIdentifier));
        }
        if(clientMode) {
            return new ClientServerHello(localIdentifier, remoteIdentifier);
        }
        else {
            return new ClientServerHello(remoteIdentifier, localIdentifier);
        }
    }

    /**
     * @return Returns the client_versioncomment.
     */
    public byte[] getClientString() {
        return StringEncoder.GetBytes(client_line);
    }

    /**
     * @return Returns the server_versioncomment.
     */
    public byte[] getServerString() {
        return StringEncoder.GetBytes(server_line);
    }
}
