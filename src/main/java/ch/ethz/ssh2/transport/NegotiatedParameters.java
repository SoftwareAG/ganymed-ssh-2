/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.transport;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public class NegotiatedParameters
{
	public boolean guessOK;
	public String kex_algo;
	public String server_host_key_algo;
	public String enc_algo_client_to_server;
	public String enc_algo_server_to_client;
	public String mac_algo_client_to_server;
	public String mac_algo_server_to_client;
	public String comp_algo_client_to_server;
	public String comp_algo_server_to_client;
	public String lang_client_to_server;
	public String lang_server_to_client;

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("NegotiatedParameters{");
        sb.append("guessOK=").append(guessOK);
        sb.append(", kex_algo='").append(kex_algo).append('\'');
        sb.append(", server_host_key_algo='").append(server_host_key_algo).append('\'');
        sb.append(", enc_algo_client_to_server='").append(enc_algo_client_to_server).append('\'');
        sb.append(", enc_algo_server_to_client='").append(enc_algo_server_to_client).append('\'');
        sb.append(", mac_algo_client_to_server='").append(mac_algo_client_to_server).append('\'');
        sb.append(", mac_algo_server_to_client='").append(mac_algo_server_to_client).append('\'');
        sb.append(", comp_algo_client_to_server='").append(comp_algo_client_to_server).append('\'');
        sb.append(", comp_algo_server_to_client='").append(comp_algo_server_to_client).append('\'');
        sb.append(", lang_client_to_server='").append(lang_client_to_server).append('\'');
        sb.append(", lang_server_to_client='").append(lang_server_to_client).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
