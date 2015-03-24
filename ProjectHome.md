## WHAT TrueCrack IS? - NEW VERSION 3.5 AVAILABLE ##
TrueCrack is a brute-force password cracker for TrueCrypt (Copyrigth) volumes. It works on Linux and it is optimized for Nvidia Cuda technology.
It supports:
  * PBKDF2 (defined in PKCS5 v2.0) based on key derivation functions: Ripemd160, Sha512 and Whirlpool.
  * XTS block cipher mode for hard disk encryption based on encryption algorithms: AES, SERPENT, TWOFISH.
  * File-hosted (container) and Partition/device-hosted.
  * Hidden volumes and Backup headers.
TrueCrack is able to perform a brute-force attack based on:
  * Dictionary: read the passwords from a file of words.
  * Alphabet: generate all passwords of given length from given alphabet.
TrueCrack works on gpu and cpu. TrueCrack requires a lots of resources: we suggest a dedicated gpu board.

## PERFORMANCE ##
The execution time of TrueCrack for a dictionary attack is (average word length 10 characters):<br>
<table><thead><th>        </th><th> <b>CPU 3.00GHz</b>      </th><th> <b>GTX650</b>   </th><th> <b>GTX680</b>   </th></thead><tbody>
<tr><td> 1000   </td><td> 0m 12.031s </td><td> 0m  3.771s </td><td> 0m  2.693s </td></tr>
<tr><td> 10000  </td><td> 2m  0.421s </td><td> 0m 15.893s </td><td> 0m  5.628s </td></tr>
<tr><td> 100000 </td><td> 20 m3.811s </td><td> 2m 20.379s </td><td> 0m 37.610s </td></tr></tbody></table>

<h2>HOW TO RUN?</h2>
Dictionary attack:<br>
<ul><li>truecrack -t truecrypt_file -w passwords_file [-k ripemd160 | -k sha512 | -k whirlpool] [-e aes | -e serpent | -e twofish] [-a blocks] [-b] [-H] [-r number]<br>
Alphabet attack:<br>
</li><li>truecrack -t truecrypt_file -c alphabet [-s minlength] -m maxlength [-k ripemd160 | -k sha512 | -k whirlpool] [-e aes | -e serpent | -e twofish] [-a blocks] [-b] [-H] [-r number]</li></ul>

<h2>HOW TO USAGE?</h2>
<table><thead><th> -h </th><th>     --help                                 </th><th> Display this information.</th></thead><tbody>
<tr><td> -t </td><td>     --truecrypt <br>
<br>
<truecrypt_file><br>
<br>
           </td><td> Truecrypt volume file.</td></tr>
<tr><td> -k </td><td>     --key <ripemd160 | sha512 | whirlpool> </td><td> Key derivation function (default ripemd160).</td></tr>
<tr><td> -e </td><td>     --encryption <aes | serpent | twofish> </td><td> Encryption algorithm (default aes).</td></tr>
<tr><td> -a </td><td>     --aggressive <br>
<br>
<blocks><br>
<br>
                  </td><td> Number of parallel computations (board dependent).</td></tr>
<tr><td> -w </td><td>     --wordlist <br>
<br>
<wordlist_file><br>
<br>
             </td><td> File of words, for Dictionary attack.</td></tr>
<tr><td> -c </td><td>     --charset <br>
<br>
<alphabet><br>
<br>
                   </td><td> Alphabet generator, for Alphabet attack.</td></tr>
<tr><td> -m </td><td>     --maxlength <br>
<br>
<maxlength><br>
<br>
                </td><td> Maximum length of passwords, for Alphabet attack.</td></tr>
<tr><td> -s </td><td>     --startlength <br>
<br>
<minlength><br>
<br>
              </td><td> Starting length of passwords, for Alphabet attack (default 1).</td></tr>
<tr><td> -r </td><td>     --restore <br>
<br>
<number><br>
<br>
                     </td><td> Restore the computation.</td></tr>
<tr><td> -b </td><td>     --backup                               </td><td> Backup header instead of volume header.</td></tr>
<tr><td> -H </td><td>     --hidden                               </td><td> Hidden Truecrypt volume.</td></tr>
<tr><td> -v </td><td>     --verbose                              </td><td> Show verbose messages.</td></tr></tbody></table>


<h2>HOW TO INSTALL?</h2>
<code>cd truecrack</code><br>
<code>./configure</code><br>
<code>make</code> <br>
<code>sudo make install</code><br>

<h2>HOW TO CONFIGURE?</h2>
<code>./configure</code> <br>
<code>  --enable-debug   : enable nVidia CUDA debug mode [default=no]</code><br>
<code>  --enable-cpu     : disable cuda nvidia GPU and use CPU [default=no]</code><br>
<code>  --with-cuda=PATH : prefix where cuda is installed [default=auto]</code><br>


<h2>LICENSE</h2>
TrueCrack is an Open Source Software under GNU Public License version 3.<br>
This software is Based on TrueCrypt, freely available at <a href='http://www.truecrypt.org'>http://www.truecrypt.org</a> <br> <br>

This is not an organization and there are not sponsor.<br>
Help us to continue to develop the software: it is necessary to buy new nvidia boards.<br>Please contact us: infotruecrack@gmail.com <br>
Twitter: <a href='https://twitter.com/TrueCrack1'>https://twitter.com/TrueCrack1</a><br>