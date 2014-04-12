package ch.ethz.ssh2.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;

import ch.ethz.ssh2.DHGexParameters;
import ch.ethz.ssh2.ServerHostKeyVerifier;
import ch.ethz.ssh2.crypto.CryptoWishList;

/**
 * @version $Id$
 */
public class ClientTransportManager extends TransportManager
{

	protected final Socket sock = new Socket();

	public void setTcpNoDelay(boolean state) throws IOException
	{
		sock.setTcpNoDelay(state);
	}

	public void setSoTimeout(int timeout) throws IOException
	{
		sock.setSoTimeout(timeout);
	}

	public void connect(String hostname, int port, String softwareversion, CryptoWishList cwl,
						ServerHostKeyVerifier verifier, DHGexParameters dhgex, int connectTimeout, SecureRandom rnd)
			throws IOException
	{
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
	public void close(final Throwable cause, final boolean useDisconnectPacket)
	{
		this.close(sock, cause, useDisconnectPacket);
	}

	protected void connect(String hostname, int port, int connectTimeout)
			throws IOException
	{
		sock.connect(new InetSocketAddress(hostname, port), connectTimeout);
	}
}