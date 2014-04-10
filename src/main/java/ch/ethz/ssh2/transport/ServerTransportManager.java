package ch.ethz.ssh2.transport;

import java.io.IOException;
import java.net.Socket;

import ch.ethz.ssh2.server.ServerConnectionState;

/**
 * @version $Id:$
 */
public class ServerTransportManager extends TransportManager {

    private final Socket sock;

    public ServerTransportManager(final Socket socket) {
        // TCP connection is already established
        this.sock = socket;
    }

    public void connect(ServerConnectionState state) throws IOException {
           /* Parse the client line and say hello - important: this information is later needed for the
   		 * key exchange (to stop man-in-the-middle attacks) - that is why we wrap it into an object
   		 * for later use.
   		 */

        state.csh = ClientServerHello.serverHello(state.softwareversion, sock.getInputStream(), sock.getOutputStream());

        TransportConnection tc = new TransportConnection(sock.getInputStream(), sock.getOutputStream(), state.generator);
        KexManager km = new ServerKexManager(state);

        super.init(tc, km);

        km.initiateKEX(state.next_cryptoWishList, null, state.next_dsa_key, state.next_rsa_key);

        this.startReceiver();
    }

    @Override
    public void close(final Throwable cause, final boolean useDisconnectPacket) {
        this.close(sock, cause, useDisconnectPacket);
    }
}
