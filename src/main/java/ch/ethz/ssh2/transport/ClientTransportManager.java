package ch.ethz.ssh2.transport;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;

import ch.ethz.ssh2.DHGexParameters;
import ch.ethz.ssh2.ServerHostKeyVerifier;
import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.util.Tokenizer;

/**
 * @version $Id:$
 */
public class ClientTransportManager extends TransportManager {

    protected final Socket sock = new Socket();

    public void setTcpNoDelay(boolean state) throws IOException {
        sock.setTcpNoDelay(state);
    }

    public void setSoTimeout(int timeout) throws IOException {
        sock.setSoTimeout(timeout);
    }

    public void connect(String hostname, int port, String softwareversion, CryptoWishList cwl,
                        ServerHostKeyVerifier verifier, DHGexParameters dhgex, int connectTimeout, SecureRandom rnd)
            throws IOException {
        // Establish the TCP connection to the SSH-2 server
        this.connect(hostname, port, connectTimeout);

        // Parse the server line and say hello - important: this information is later needed for the
        // key exchange (to stop man-in-the-middle attacks) - that is why we wrap it into an object
        // for later use.

        ClientServerHello csh = ClientServerHello.clientHello(softwareversion, sock.getInputStream(),
                sock.getOutputStream());

        TransportConnection tc = new TransportConnection(sock.getInputStream(), sock.getOutputStream(), rnd);

        KexManager km = new ClientKexManager(this, csh, cwl, hostname, port, verifier, rnd);
        super.init(tc, km);

        km.initiateKEX(cwl, dhgex, null, null);

        this.startReceiver();
    }

    @Override
    public void close(final Throwable cause, final boolean useDisconnectPacket) {
        this.close(sock, cause, useDisconnectPacket);
    }

    protected void connect(String hostname, int port, int connectTimeout)
            throws IOException {

        InetAddress addr = createInetAddress(hostname);
        sock.connect(new InetSocketAddress(addr, port), connectTimeout);
    }

    /**
     * There were reports that there are JDKs which use
     * the resolver even though one supplies a dotted IP
     * address in the Socket constructor. That is why we
     * try to generate the InetAdress "by hand".
     *
     * @param host
     * @return the InetAddress
     * @throws java.net.UnknownHostException
     */
    protected static InetAddress createInetAddress(String host) throws UnknownHostException {
           /* Check if it is a dotted IP4 address */

        InetAddress addr = parseIPv4Address(host);

        if(addr != null) {
            return addr;
        }

        return InetAddress.getByName(host);
    }

    private static InetAddress parseIPv4Address(String host) throws UnknownHostException {
        if(host == null) {
            return null;
        }

        String[] quad = Tokenizer.parseTokens(host, '.');

        if((quad == null) || (quad.length != 4)) {
            return null;
        }

        byte[] addr = new byte[4];

        for(int i = 0; i < 4; i++) {
            int part = 0;

            if((quad[i].length() == 0) || (quad[i].length() > 3)) {
                return null;
            }

            for(int k = 0; k < quad[i].length(); k++) {
                char c = quad[i].charAt(k);

   				/* No, Character.isDigit is not the same */
                if((c < '0') || (c > '9')) {
                    return null;
                }

                part = part * 10 + (c - '0');
            }

            if(part > 255) /* 300.1.2.3 is invalid =) */ {
                return null;
            }

            addr[i] = (byte) part;
        }

        return InetAddress.getByAddress(host, addr);
    }
}