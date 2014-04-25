package com.github.fichtner.crackgpg.gnupg.main;

import static com.github.pfichtner.durationformatter.DurationFormatter.SuppressZeros.LEADING;
import static com.github.pfichtner.durationformatter.DurationFormatter.SuppressZeros.MIDDLE;
import static com.github.pfichtner.durationformatter.DurationFormatter.SuppressZeros.TRAILING;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.util.EnumSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.openpgp.PGPException;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.OptionHandlerFilter;

import com.github.fichtner.crackgpg.gnupg.GpgPassphraseChecker;
import com.github.fichtner.crackgpg.gnupg.PassphraseChecker;
import com.github.pfichtner.durationformatter.DurationFormatter;
import com.google.common.base.Throwables;

public class CrackMultiCore {

	private static class CrackResult {

		private static final CrackResult EOQ = new CrackResult(false, null);

		private final boolean hit;
		private final String passphrase;

		public CrackResult(boolean hit, String passphrase) {
			this.hit = hit;
			this.passphrase = passphrase;
		}

		public boolean isHit() {
			return hit;
		}

		public String getPassphrase() {
			return passphrase;
		}

	}

	private static class PassphraseCallable implements Callable<CrackResult> {

		private final PassphraseChecker passphraseChecker;
		private final String passphrase;

		public PassphraseCallable(PassphraseChecker passphraseChecker,
				String passphrase) {
			this.passphraseChecker = passphraseChecker;
			this.passphrase = passphrase;
		}

		@Override
		public CrackResult call() throws Exception {
			return new CrackResult(passphraseChecker.checkPassphrase(passphrase
					.toCharArray()), passphrase);
		}

	}

	@Option(name = "-f", usage = "secring to read", required = false)
	private File secring = new File(new File(System.getProperty("user.home"),
			".gnupg"), "secring.gpg");

	@Option(name = "-k", usage = "key to read", required = false)
	private String keyId;

	@Option(name = "-h", usage = "halt on first hit", required = false)
	private boolean haltOnFirstHit = true;

	@Option(name = "-c", usage = "cores to use", required = false)
	private int cores = Runtime.getRuntime().availableProcessors();

	public static void main(String[] args) throws FileNotFoundException,
			IOException, PGPException, InterruptedException, ExecutionException {
		new CrackMultiCore().doMain(args);
	}

	private void doMain(String[] args) throws FileNotFoundException,
			IOException, PGPException, InterruptedException, ExecutionException {
		CmdLineParser cmdLineParser = new CmdLineParser(this);

		try {
			cmdLineParser.parseArgument(args);
		} catch (CmdLineException e) {
			System.err.println(e.getMessage());
			cmdLineParser.printUsage(System.err);
			cmdLineParser.printExample(OptionHandlerFilter.ALL);
			return;
		}

		final PassphraseChecker passphraseChecker = createPassphraseChecker();

		BlockingQueue<Runnable> blockingQueue = new ArrayBlockingQueue<Runnable>(
				16 * cores);
		ExecutorService executorService = new ThreadPoolExecutor(this.cores,
				this.cores, 0L, TimeUnit.MILLISECONDS, blockingQueue,
				new ThreadPoolExecutor.CallerRunsPolicy());

		final ExecutorCompletionService<CrackResult> ecs = new ExecutorCompletionService<CrackResult>(
				executorService);

		BufferedReader reader = new BufferedReader(new InputStreamReader(
				System.in));
		String line = reader.readLine();

		// the first thing to try EVERTIME should be the empty passphrase
		ecs.submit(new PassphraseCallable(passphraseChecker, ""));

		BigDecimal phrasesToTry = tryReadPhrasesToTry(reader, line);
		if (phrasesToTry == null) {
			ecs.submit(new PassphraseCallable(passphraseChecker, line));
		}
		// push in background thread
		Thread backgroundPusher = pushInBackground(passphraseChecker, ecs,
				reader);

		BigDecimal probedPassphrases = new BigDecimal(0);
		long startTime = System.currentTimeMillis();
		long nextSysout = nextSysout(startTime);

		DurationFormatter df = DurationFormatter.Builder.SYMBOLS
				.minimum(TimeUnit.SECONDS).maximum(TimeUnit.DAYS)
				.suppressZeros(EnumSet.of(LEADING, MIDDLE, TRAILING))
				.maximumAmountOfUnitsToShow(2).build();

		while (true) {
			CrackResult result = ecs.take().get();
			if (result == CrackResult.EOQ) {
				System.out.println("Passphrase not found");
				shutdown(backgroundPusher, executorService);
				return;
			}
			String passphrase = result.getPassphrase();
			if (result.isHit()) {
				System.out.println("Passphrase found: \"" + passphrase + "\"");
				if (haltOnFirstHit) {
					shutdown(backgroundPusher, executorService);
					return;
				}
			}

			probedPassphrases = probedPassphrases.add(BigDecimal.ONE);
			long now = System.currentTimeMillis();
			if (now >= nextSysout) {
				long millisRun = now - startTime;
				double keysPerMillis = probedPassphrases.doubleValue()
						/ millisRun;

				if (keysPerMillis > 0) {
					String timeLeft = "";
					String ofPhrases = "";
					if (phrasesToTry != null) {
						timeLeft = ", time left: "
								+ df.format(
										phrasesToTry
												.subtract(probedPassphrases)
												.divide(new BigDecimal(
														keysPerMillis),
														BigDecimal.ROUND_HALF_UP)
												.longValue(),
										TimeUnit.MILLISECONDS);
						ofPhrases = " of " + phrasesToTry;
					}

					System.out.println("Try #" + probedPassphrases + ofPhrases
							+ " @" + (int) (keysPerMillis * 1000) + " keys/s "
							+ passphrase + ", time spent: "
							+ df.formatMillis(millisRun) + timeLeft);
				}

				nextSysout = nextSysout(now);
			}

		}

	}

	public BigDecimal tryReadPhrasesToTry(BufferedReader reader, String line)
			throws IOException {
		if (line.contains("will now generate the following amount of data")) {
			while ((line = reader.readLine()) != null) {
				// Crunch will now generate the following number of lines: 9
				if (line.contains("will now generate the following number of lines")) {
					String[] split = line.split(":");
					if (split.length == 2) {
						try {
							return new BigDecimal(split[1].trim());
						} catch (NumberFormatException e) {
							// do nothing
						}
					}
				}
			}
		}
		return null;
	}

	private void shutdown(Thread backgroundPusher,
			ExecutorService executorService) {
		backgroundPusher.interrupt();
		executorService.shutdownNow();
	}

	private Thread pushInBackground(final PassphraseChecker passphraseChecker,
			final ExecutorCompletionService<CrackResult> ecs,
			final BufferedReader reader) {
		return new Thread() {
			{
				start();
			}

			public void run() {
				String line;
				try {
					while ((line = reader.readLine()) != null) {
						ecs.submit(new PassphraseCallable(passphraseChecker,
								line));
					}
				} catch (IOException e) {
					throw Throwables.propagate(e);
				}

				// push End Of Queue
				ecs.submit(new Callable<CrackResult>() {
					@Override
					public CrackResult call() throws Exception {
						return CrackResult.EOQ;
					}
				});
			};
		};
	}

	private long nextSysout(long startTime) {
		return startTime + 1000;
	}

	private PassphraseChecker createPassphraseChecker()
			throws FileNotFoundException, IOException, PGPException {
		FileInputStream keyInputStream = new FileInputStream(secring);
		try {
			return new GpgPassphraseChecker(keyInputStream, keyId);
		} finally {
			keyInputStream.close();
		}
	}

}
