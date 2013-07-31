/*
 * Copyright (c) 2006-2013 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Random;

import ch.ethz.ssh2.ConnectionInfo;
import ch.ethz.ssh2.PtySettings;
import ch.ethz.ssh2.ServerAuthenticationCallback;
import ch.ethz.ssh2.ServerConnection;
import ch.ethz.ssh2.ServerConnectionCallback;
import ch.ethz.ssh2.ServerSession;
import ch.ethz.ssh2.ServerSessionCallback;
import ch.ethz.ssh2.SimpleServerSessionCallback;
import ch.ethz.ssh2.signature.RSAPrivateKey;

public class BasicServer implements ServerAuthenticationCallback, ServerConnectionCallback
{
	private static final int SERVER_PORT = 2222;
	private static final String AUTH_USER = "root";
	private static final String AUTH_PASS = "kensentme";
	
	public static void main(String[] args) throws IOException
	{
		BasicServer bs = new BasicServer();
		bs.acceptSingleConnection();
	}

	private static  ServerConnection conn = null;
	
	private void acceptSingleConnection() throws IOException
	{
		System.out.println("Generating RSA private key...");
		System.out.flush();

		/* Generate random RSA private key */

		Random rnd = new SecureRandom();

		int N = 1500;
		BigInteger p = BigInteger.probablePrime(N / 2, rnd);
		BigInteger q = BigInteger.probablePrime(N / 2, rnd);
		BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

		BigInteger n = p.multiply(q);
		BigInteger e = new BigInteger("65537");
		BigInteger d = e.modInverse(phi);

		RSAPrivateKey hostkey = new RSAPrivateKey(d, e, n);

		/* Accept a connection */

		System.out.println("Waiting for one (1) connection on port "+SERVER_PORT+"...");
		System.out.flush();

		ServerSocket ss = new ServerSocket(SERVER_PORT);
		Socket s = ss.accept();
		ss.close(); // We only accept one connection and immediately close the server socket
		
		/* Wrap the established socket with a SSH-2 connection */

		conn = new ServerConnection(s);
		conn.setRsaHostKey(hostkey);
		conn.setAuthenticationCallback(this);
		conn.setServerConnectionCallback(this);

		/* Do the kex exchange and asynchronously start processing requests */

		System.out.println("Doing key exchange with client...");
		System.out.flush();
		
		conn.connect();

		/* Show some information about the connection */

		ConnectionInfo info = conn.getConnectionInfo();

		System.out.println("Kex Algo:             " + info.keyExchangeAlgorithm);
		System.out.println("Kex Count:            " + info.keyExchangeCounter);
		System.out.println("Server Host Key Algo: " + info.serverHostKeyAlgorithm);
		System.out.println("C2S Crypto Algo:      " + info.clientToServerCryptoAlgorithm);
		System.out.println("C2S MAC Algo:         " + info.clientToServerMACAlgorithm);
		System.out.println("S2C Crypto Algo:      " + info.serverToClientCryptoAlgorithm);
		System.out.println("S2C MAC Algo:         " + info.serverToClientMACAlgorithm);
		System.out.flush();
		
		/* The connection is working, have fun and force a key exchange every few
		 * seconds to test whether the client is implemented correctly...
		 */
		
		while (true)
		{
			try
			{
				Thread.sleep(10000);
			}
			catch (InterruptedException e1)
			{
			}
			
			System.out.println("Forcing key exchange with client...");
			System.out.flush();
			
			conn.forceKeyExchange();
		}
	}

	public ServerSessionCallback acceptSession(final ServerSession session)
	{
		SimpleServerSessionCallback cb = new SimpleServerSessionCallback()
		{
			@Override
			public boolean allowPtyReq(ServerSession ss, PtySettings pty) throws IOException
			{
				return true;
			}

			@Override
			public void handlePtyReq(ServerSession ss, PtySettings pty) throws IOException
			{
			}

			@Override
			public boolean allowShell(ServerSession ss) throws IOException
			{
				return true;
			}

			@Override
			public void handleShell(final ServerSession ss) throws IOException
			{
				Thread tr = new Thread(new Runnable()
				{
					public void run()
					{
						try
						{
							while (true)
							{
								int c = ss.getStdout().read();
								if (c < 0)
								{
									System.err.println("SESSION EOF");
									return;
								}
								
								ss.getStdin().write(("You typed " + c + "\r\n").getBytes());
							}

						}
						catch (IOException e)
						{
							System.err.println("SESSION DOWN");
							e.printStackTrace();
						}
					}
				});
				tr.setDaemon(true);
				tr.start();
			}
		};

		return cb;
	}

	public String initAuthentication(ServerConnection sc)
	{
		return "=====================================\r\nWelcome to the Ganymed SSH Server\r\nBeware of the barking dog!\r\n=====================================\r\n";
	}

	public String[] getRemainingAuthMethods(ServerConnection sc)
	{
		return new String[] { ServerAuthenticationCallback.METHOD_PASSWORD,
				ServerAuthenticationCallback.METHOD_PUBLICKEY };
	}

	public boolean authenticateWithNone(ServerConnection sc, String username)
	{
		return false;
	}

	public boolean authenticateWithPassword(ServerConnection sc, String username, String password)
	{
		return AUTH_USER.equals(username) && AUTH_PASS.equals(password);
	}

	public boolean authenticateWithPublicKey(ServerConnection sc, String username, String algorithm, byte[] publickey,
			byte[] signature)
	{
		/* Isn't that a bit unfair? We offer public key authentication, but deny every attempt =) */
		return false;
	}
}
