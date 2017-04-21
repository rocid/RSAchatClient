import java.io.Serializable;
import java.security.Key;

public class Message implements Serializable{	
	String dst_addr;	
	int dst_port;
	String src_addr;	
	int src_port;	
	String type;
	String msg;
	Key public_key;
	
	public Message(String d_a, int d_p, String s_a, int s_p, String t, String m, Key p_k){
		dst_addr = d_a;
		dst_port = d_p;
		src_addr = s_a;
		src_port = s_p;		
		type = t;
		msg = m;
		public_key = p_k;
	}
}
