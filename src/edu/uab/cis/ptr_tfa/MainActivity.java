package edu.uab.cis.ptr_tfa;


import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.ECPoint;

import org.spongycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;

public class MainActivity extends Activity {
	
//	public static final int NUM_ITERS = 10000;	

	static {
	    Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
				
		Button b = (Button) findViewById(R.id.button1);
//		Button b = (Button) findViewById(R.id.button2);

		b.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {
				
		        OPRF();

		        
//				long startTime = 0;
//				long endTime = 0;
//				double averageTime = 0;
//				ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(Constants.CURVE_NAME);
//				ECCurve curve = ecSpec.getCurve();
//				java.security.spec.ECPoint ecPoint = new ECPoint
//								(new BigInteger("0000000005157E4295D6FF0C5B3D9D00FA1B0D76A04ADBF90252C748B2C46850BDCF32AFBF9C5AAB", 16), 
//								 new BigInteger("0000000002A28F1B83177FAC4824222D412B691FA51524DF126D535AFF08BB739A9F304A236397AF", 16));
//				org.spongycastle.math.ec.ECPoint ecNewPoint  = EC5Util.convertPoint(curve, ecPoint, false);
//
//				startTime = System.currentTimeMillis();//.nanoTime();
//				for (int i = 0 ; i <NUM_ITERS; i++) {
//					
//					if (pointMember(curve, ecNewPoint)) {
//						System.out.println("point is on the curve");
////						String betaStr = OPRF_Encode(new BigInteger(Constants.OPRF_KEY, 16), ecNewPoint);
//					} else  {
//						System.out.println("point not on the curve");
//					}
//					
//
//				}
//				endTime = System.currentTimeMillis();//.nanoTime();
//				averageTime = (endTime - startTime) /NUM_ITERS;
//				Log.e ("timing", "membership checking takes " + averageTime + " milli second" );

			}

			public void OPRF() {
				String challenge = new String();
				try {
					challenge = getAlpha();
				} catch (UnknownHostException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SocketException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		        try {
					sendBeta(challenge.substring(4));
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});	
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}
	
	
	public static String getAlpha() throws UnknownHostException,
	SocketException, IOException {
		byte[] receiveData = new byte[1024];
		InetAddress deviceAddr = InetAddress.getByName(Constants.DEVICEIP);
		DatagramSocket socket = new DatagramSocket(Constants.DEVICEPORT, deviceAddr);
		
		//while(true) {
		  DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		  socket.receive(receivePacket);
		  String challenge = new String(receivePacket.getData());
		  System.out.println("Received Alpha: " + challenge);
		  socket.close();
		return challenge;
	}

	private static void sendBeta(String alpha) throws IOException, NoSuchAlgorithmException {	
		ECCurve curve = getCurve(Constants.CURVE_NAME);
		org.spongycastle.math.ec.ECPoint ecPoint = decodePoint(curve, alpha);
//		if (pointMember(curve, ecPoint)) {
			String betaStr = multy(new BigInteger(Constants.OPRF_KEY, 16), ecPoint);
			byte[] beta = betaStr.getBytes();
		
			DatagramSocket socket = new DatagramSocket();
		    InetAddress clientIPAddress = InetAddress.getByName(Constants.CLIENTIP);	    
		    
		    DatagramPacket sendPacket = new DatagramPacket(beta, beta.length, clientIPAddress, Constants.CLIENTPORT);
			socket.send(sendPacket);
			System.out.println("Sent Beta");
			socket.close(); 
//		} else  {
//			System.out.println("point not on the curve");
//		}
	}
	public static boolean pointMember(ECCurve curve, org.spongycastle.math.ec.ECPoint point) {
		
		ECFieldElement x = point.getAffineXCoord();
		ECFieldElement y = point.getAffineYCoord();

		ECFieldElement a = curve.getA();
		ECFieldElement b = curve.getB();
		ECFieldElement lhs = y.multiply(y);
		ECFieldElement rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b);

		boolean pointIsOnCurve = lhs.equals(rhs);
			
		return pointIsOnCurve;
	}
	
	// OPRF = F_k(x) = H(x, H'(x)^k)
	public static String OPRF_Encode(BigInteger key, org.spongycastle.math.ec.ECPoint point) throws NoSuchAlgorithmException {
		return Hash(encodePoint(point), multy(key, point)); //infact if should be multy(key, H'(point)) currently I don't have H' implementation
	}
	
//	// subF_k(x) = H'(x)^k
//	public static org.spongycastle.math.ec.ECPoint subOPRF(BigInteger key, org.spongycastle.math.ec.ECPoint point) {
//		org.spongycastle.math.ec.ECPoint multiplier = point.multiply(key);
//		return multiplier;
//	}
	
	// multy(x) = x^k
	public static String multy(BigInteger key, org.spongycastle.math.ec.ECPoint point) {
		org.spongycastle.math.ec.ECPoint multiplier = point.multiply(key);
		return encodePoint(multiplier);
	}
	

	
	public static ECCurve getCurve(String curveName) {
		
		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
		ECCurve curve = ecSpec.getCurve();
		return curve;
	}
	
	public static org.spongycastle.math.ec.ECPoint decodePoint(ECCurve curve, String challenge) {
		String[] rcvdStr = challenge.split(",");
		BigInteger x = new BigInteger(rcvdStr[0], 16);
		BigInteger y = new BigInteger(rcvdStr[1], 16);
		
		java.security.spec.ECPoint ecPoint = new ECPoint(x, y);
		org.spongycastle.math.ec.ECPoint ecNewPoint  = EC5Util.convertPoint(curve, ecPoint, false);
		return ecNewPoint;
	}
	
	private static byte[] getHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result.getBytes();
	}
	
	private static String encodePoint(org.spongycastle.math.ec.ECPoint point) {
		// TODO Auto-generated method stub
		BigInteger x = point.getAffineXCoord().toBigInteger();
		BigInteger y = point.getAffineYCoord().toBigInteger();
		String hexStrEncoding = x.toString(16).concat(",").concat(y.toString(16));
		return hexStrEncoding;
	}
	
	public static String Hash(String seed, String message) throws NoSuchAlgorithmException {
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		String x = message + seed;
		messageDigest.update(x.getBytes());
		return byteArray2Hex(messageDigest.digest());		
	}
	

	private static final char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	public static String byteArray2Hex(byte[] bytes) {
	    StringBuffer sb = new StringBuffer(bytes.length * 2);
	    for(final byte b : bytes) {
	        sb.append(hex[(b & 0xF0) >> 4]);
	        sb.append(hex[b & 0x0F]);
	    }
	    return sb.toString();
	}
	
}
