# iiaom

Cryptoidentity for everyone. [the idea](http://namzezam.wikidot.com/blog:12).

## License

You are not allowed to use, produce from or design from this or its part, anything contained with the aim to kill,to cause harm to or to monitor people and any permission beside that is given only under the [AGPL License](http://www.gnu.org/licenses/agpl-3.0.html)!

## todo:
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

Also see http://namzezam.wikidot.com/blog:12#last-minit-note

## Install

npm install -g git://github.com/yetzt/iiaom.git

## How-to

http://iiaom.wikidot.com/
