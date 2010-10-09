package net.vvakame.lvlmin;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.text.TextUtils;
import android.util.Log;

import com.android.vending.licensing.ResponseData;
import com.android.vending.licensing.util.Base64;
import com.android.vending.licensing.util.Base64DecoderException;

final public class LicensingUtil {

	public static final String BASE64_PUBLIC_KEY = "REPLACE YOUR OWN PUBLIC KEY http://market.android.com/publish/editProfile";

	public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	public static final String KEY_FACTORY_ALGORITHM = "RSA";

	// Server response codes.
	public static final int LICENSED = 0x0;
	public static final int NOT_LICENSED = 0x1;
	public static final int LICENSED_OLD_KEY = 0x2;
	public static final int ERROR_NOT_MARKET_MANAGED = 0x3;
	public static final int ERROR_SERVER_FAILURE = 0x4;
	public static final int ERROR_OVER_QUOTA = 0x5;

	public static final int ERROR_CONTACTING_SERVER = 0x101;
	public static final int ERROR_INVALID_PACKAGE_NAME = 0x102;
	public static final int ERROR_NON_MATCHING_UID = 0x103;

	private static final String TAG = "LVLVerify";

	private LicensingUtil() {
	}

	public static boolean verify(int responseCode, String signedData,
			String signature, Context con, String verifyPackageName,
			int verifyNonce) {

		// 正規か判断する LICENSED と NOT_LICENSED と LICENSED_OLD_KEY が正常系データ
		// LICENSED_OLD_KEY は多分、購入者だけど古いVersionのapk使ってる場合
		if (responseCode != LICENSED) {
			Log.d(TAG, "not valid licensing status!");
			return false;
		}

		// 署名の確認
		try {
			Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
			PublicKey key = null;
			{
				byte[] decodedKey = Base64.decode(BASE64_PUBLIC_KEY);
				KeyFactory keyFactory = KeyFactory
						.getInstance(KEY_FACTORY_ALGORITHM);

				key = keyFactory.generatePublic(new X509EncodedKeySpec(
						decodedKey));
			}
			sig.initVerify(key);
			sig.update(signedData.getBytes());

			if (!sig.verify(Base64.decode(signature))) {
				Log.e(TAG, "Signature verification failed.");
				return false;
			}
		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, e.getMessage(), e);
			return false;
		} catch (Base64DecoderException e) {
			Log.e(TAG, e.getMessage(), e);
			return false;
		} catch (InvalidKeyException e) {
			Log.e(TAG, e.getMessage(), e);
			return false;
		} catch (InvalidKeySpecException e) {
			Log.e(TAG, e.getMessage(), e);
			return false;
		} catch (SignatureException e) {
			Log.e(TAG, e.getMessage(), e);
			return false;
		}

		// レスポンスの解釈と検証
		ResponseData data = null;
		try {
			data = ResponseData.parse(signedData);
		} catch (IllegalArgumentException e) {
			Log.e(TAG, "Could not parse response.");
			return false;
		}

		if (data.responseCode != responseCode) {
			Log.e(TAG, "Response codes don't match.");
			return false;
		}

		if (data.nonce != verifyNonce) {
			Log.e(TAG, "Nonce doesn't match.");
			return false;
		}

		if (!data.packageName.equals(verifyPackageName)) {
			Log.e(TAG, "Package name doesn't match.");
			return false;
		}

		try {
			String versionCode = String.valueOf(con.getPackageManager()
					.getPackageInfo(verifyPackageName, 0).versionCode);
			if (!data.versionCode.equals(versionCode)) {
				Log.e(TAG, "Version codes don't match.");
				return false;
			}
		} catch (NameNotFoundException e) {
			Log.e(TAG, e.getMessage(), e);
			return false;
		}

		// Application-specific user identifier.
		String userId = data.userId;
		if (TextUtils.isEmpty(userId)) {
			Log.e(TAG, "User identifier is empty.");
			return false;
		}

		Log.d(TAG, "This user is valid user!!");
		return true;
	}
}
