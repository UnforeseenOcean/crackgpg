package com.github.fichtner.crackgpg.gnupg;

public interface PassphraseChecker {

	boolean checkPassphrase(char[] pass);

}