#!/usr/bin/env node

/*
todo:
 this protocol must be performed only in a mutual verifying,
 where H (human) is also V(verifier) and vs,    for making it  more expensive for the mass attackers!
1 H: in create <file> to make the hash of both the encrypted and the source and if it was not "safe" still to ask to delete to source!!
2.V: another option - get(encrypted, pubkey )
    sending to H encrypted asymmetrically the symmetrically encrypted file
2.H: another option - give(pubkey, encrypted file)
    sending to V encrypted asymmetrically the file
3. V: in verify
  1. hash both the encrypted and the non encrypted to match the iiaom
  2. try match by other means the human with the pic
  3. sign the iiaom on matching

4. after signing the iiaom (being hash both encrypted and source) should be hashed again and
put in encrypted dir/db or table having also counter (of normality) +optionally with date and notes.
    1, this would  allow measurement of
        1, integer: any time publicly, trust of the human=  number of unique trustees
        2, integer: any time internally, counter normality with trustee= the number of being singed by trustee
        3. percentage:  when the normality is high, between 2 how match they are related per each=
            of those sining me how much singed you
             more related to other probebly more attracted to the other !?

*/

/* node modules */
var fs = require("fs");
var path = require("path");
var crypto = require("crypto");

/* npm modules */
var openpgp = require("openpgp");
var archiver = require("archiver");

/* require package.json */
var pkg = require(path.resolve(__dirname, "..", "package.json"));

function iiaom(config, callback){
	
	if (!(this instanceof iiaom)) return new iiaom(config, callback);
	
	var self = this;
	
	var pubkey_file = path.resolve(__dirname, "..", "etc", "pubkey.asc");
	if (config && config.hasOwnProperty("pubkey") && typeof config.pubkey === "string") pubkey_file = path.resolve(process.cwd(), config.pubkey);

	fs.exists(pubkey_file, function(exists){
		if (!exists) return callback(new Error("pubkey file not found: "+pubkey_file));
		fs.readFile(pubkey_file, function(err, pubkey_data){
			if (err) return callback(err);
			self.pubkey = openpgp.key.readArmored(pubkey_data.toString()).keys;
			callback(null, self);
		});
	});
	
	return this;
	
};

iiaom.prototype.verify = function(file, password, callback){
	var self = this;
	/* unzip, decrypt, hash, compare */
	return self;
};

iiaom.prototype.generate = function(file, password, callback){
	var self = this;
	var file = path.resolve(process.cwd(), file);
	fs.exists(file, function(exists){
		if (!exists) return callback(new Error("file not found: "+file));
		
		/* create 256 byte key from password with 1000 rounds of pbkdf2 */
		var _key = crypto.pbkdf2Sync(password, "iiaom", 1000, 256);
		
		/* sha256 hash for original file data */
		var _hash = crypto.createHash("sha256");

		/* aes256 cipher to encrypt original file data */
		var _cipher = crypto.createCipher('aes-256-cbc', _key);
		var _encrypted_aes_binary = [];

		/* array of data buffers for pgp encryption */
		var _data = [];
		
		/* read stream from original file */
		fs.createReadStream(file).on('data', function(d) { 

			/* update cipher with data chunk and write buffer to memory */
			_encrypted_aes_binary.push(new Buffer(_cipher.update(d, 'binary', 'binary'), 'binary'));

			/* update hash with data chunk */
			_hash.update(d);

			/* push chunk buffer */
			_data.push(d);
			
		}).on('end', function() {
			
			/* finalize hash of original data */
			var _sha_hash = _hash.digest('hex');
			
			var _public_hash = crypto.createHash("sha256").update(_sha_hash).update(_key).digest('hex');

			/* finalize encryption of original data and concatenate buffers */
			_encrypted_aes_binary.push(new Buffer(_cipher.final('binary'), 'binary'));
			_encrypted_aes_binary = Buffer.concat(_encrypted_aes_binary);
			

			/* finalize pgp encryption and put it in ascii armor */
			var _encrypted_pgp_binary = openpgp.message.fromBinary(Buffer.concat(_data)).encrypt(self.pubkey).packets.write()
			var _encrypted_pgp_ascii = openpgp.armor.encode(openpgp.enums.armor.message, _encrypted_pgp_binary);

			/* create hash of armored pgp */
			var _encrypted_pgp_hash = crypto.createHash("sha256").update(_encrypted_pgp_ascii).digest("hex");

			var _public_id = _public_hash+_encrypted_pgp_hash;

			/* create information */
			var _info = JSON.stringify({
				"v": pkg.fileformat,
				"id": _public_id,
				"gpgkey": self.pubkey[0].primaryKey.fingerprint
			});

			var zip = archiver('zip');

			zip.on('error', function(err) {
				console.log("zip error", err);
				process.exit(-1);
			});

			zip.pipe(fs.createWriteStream(path.resolve(process.cwd(), _public_id+'.iiaom')).on('close', function(){
				callback(null, _public_id+'.iiaom', zip.pointer());
			
			}));

			zip
				.append(_info, { name: 'iiaom.json' })
				.append(_encrypted_pgp_ascii, { name: 'encrypted.gpg' })
				.append(_encrypted_aes_binary, { name: 'encrypted.aes' })
				.finalize();
			
		});
	});
	return this;
};

iiaom.prototype.hash = function(data) {
	return crypto.createHash("sha256").update(data).digest("hex");
};

module.exports = iiaom;
