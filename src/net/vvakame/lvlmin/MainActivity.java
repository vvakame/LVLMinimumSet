package net.vvakame.lvlmin;

import java.security.SecureRandom;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import com.android.vending.licensing.ILicenseResultListener;
import com.android.vending.licensing.ILicensingService;

public class MainActivity extends Activity {

	private static final String TAG = "LVLMin";

	final private MainActivity self = this;

	private int mNonce;
	private String mPackageName;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);

		// チェックするだけで何もしない
		LicenseChecker licenseChecker = new LicenseChecker();
		licenseChecker.doCheck();
	}

	private class LicenseChecker implements ServiceConnection {

		private ILicensingService mService;

		public void doCheck() {
			boolean bindResult = bindService(
					new Intent(ILicensingService.class.getName()), this,
					Context.BIND_AUTO_CREATE);

			if (bindResult) {
				Log.d(TAG, "success!");
			} else {
				Log.e(TAG, "could not bind to service.");
			}
		}

		@Override
		public void onServiceConnected(ComponentName name, IBinder service) {
			Log.d(TAG, "licensing service connected!");

			mService = ILicensingService.Stub.asInterface(service);

			try {
				// 後で検証に使うのでとっておく
				mNonce = new SecureRandom().nextInt();
				mPackageName = self.getPackageName();
				// 検証結果をコールバックしてもらうIFを渡す
				mService.checkLicense(mNonce, mPackageName,
						new ResultListener());
			} catch (RemoteException e) {
				Log.e(TAG, "check license failed! remote exception!", e);
			}
		}

		@Override
		public void onServiceDisconnected(ComponentName name) {
			mService = null;
		}
	}

	private class ResultListener extends ILicenseResultListener.Stub {

		public ResultListener() {
			super();
			Log.d(TAG, "ResultListener constructor");
		}

		@Override
		public IBinder asBinder() {
			return this;
		}

		@Override
		public void verifyLicense(int responseCode, String signedData,
				String signature) throws RemoteException {

			Log.d(TAG, "responseCode=" + String.valueOf(responseCode));
			Log.d(TAG, "signedData=" + signedData);
			Log.d(TAG, "signature=" + signature);

			boolean verify = LicensingUtil.verify(responseCode, signedData,
					signature, self, mPackageName, mNonce);
			Log.d(TAG, "verify=" + String.valueOf(verify));
		}
	}
}