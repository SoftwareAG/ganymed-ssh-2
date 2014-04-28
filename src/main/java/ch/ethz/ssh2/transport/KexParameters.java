/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.transport;

import java.util.Arrays;

/**
 * KexParameters.
 * 
 * @author Christian Plattner
 * @version 2.50, 03/15/10
 */
public class KexParameters
{
	public byte[] cookie;
	public String[] kex_algorithms;
	public String[] server_host_key_algorithms;
	public String[] encryption_algorithms_client_to_server;
	public String[] encryption_algorithms_server_to_client;
	public String[] mac_algorithms_client_to_server;
	public String[] mac_algorithms_server_to_client;
	public String[] compression_algorithms_client_to_server;
	public String[] compression_algorithms_server_to_client;
	public String[] languages_client_to_server;
	public String[] languages_server_to_client;
	public boolean first_kex_packet_follows;
	public int reserved_field1;

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("KexParameters{");
        sb.append("cookie=").append(Arrays.toString(cookie));
        sb.append(", kex_algorithms=").append(Arrays.toString(kex_algorithms));
        sb.append(", server_host_key_algorithms=").append(Arrays.toString(server_host_key_algorithms));
        sb.append(", encryption_algorithms_client_to_server=").append(Arrays.toString(encryption_algorithms_client_to_server));
        sb.append(", encryption_algorithms_server_to_client=").append(Arrays.toString(encryption_algorithms_server_to_client));
        sb.append(", mac_algorithms_client_to_server=").append(Arrays.toString(mac_algorithms_client_to_server));
        sb.append(", mac_algorithms_server_to_client=").append(Arrays.toString(mac_algorithms_server_to_client));
        sb.append(", compression_algorithms_client_to_server=").append(Arrays.toString(compression_algorithms_client_to_server));
        sb.append(", compression_algorithms_server_to_client=").append(Arrays.toString(compression_algorithms_server_to_client));
        sb.append(", languages_client_to_server=").append(Arrays.toString(languages_client_to_server));
        sb.append(", languages_server_to_client=").append(Arrays.toString(languages_server_to_client));
        sb.append(", first_kex_packet_follows=").append(first_kex_packet_follows);
        sb.append(", reserved_field1=").append(reserved_field1);
        sb.append('}');
        return sb.toString();
    }
}
