# Sigaldry

Sigaldry[^sigaldry_name] is a cryptographic API that is designed to make it possible for non-experts
to use cryptography safely and correctly, and to support cryptography performed in secure hardware.

## API design

To enable non-experts to use cryptography safely and correctly, Sigaldry approaches the problem of
specifying cryptographic operations through security properties, called `Rune`s.  Users can specify
the security properties they want to achieve in a `Schema` (a list of Runes) and leave it to the
library to choose an appropriate cryptographic construction that satisfies their requirements.
Alternatively, users can optionally specify the construction they think they want along with the
RuneList and the library will return an error if the construction does not satisfy the Schema, which
provides confidence that the chosen construction achieves the desired goals and facilitates security
review.

Sample Runes include:

* `MessageLimit`: Number of messages (data items) that can safely be protected.
* `Confidentiality`: Protected data is kept confidential and can only be revealed by application of
  the correct cryptographic secrets.
* `Integrity`: Protected data cannot be modified without the modification being noticed when the
  data is "unsealed".
* `Authentication`:  The identity of the sender is bound to the protected data and will be verified
  when the data is "unsealed".
* `QuantumResistance`:  The security properties hold even against attack by a quantum computer.
* `Certification`:  Assurance of the security properties is provided by secure hardware with the
  specified certification.

As the `MessageLimit` and `Certification` Runes demonstrate, Runes need not be boolean-valued.  Each
specified Rune can contain Rune-specific associated data that is relevant to that security property.

Schema specification is performed at the point of key (or key pair) generation. The selection of
crytographic construction to be used with the key is performed at that time, and the chosen
construction and associated security configuration are permanently and irrevocably bound to the key,
so the generated key can only be used in the ways specified at generation.  In the language of the
API, the result of a key generation, which includes the cryptographic key and all of the bound usage
restrictions is called a `BindRune`[^bindrune_name] and creation of a BindRune is called "forging".
After forging, BindRunes are used to `seal` data, applying the protection schema, or to `unseal`
sealed data.

Sealed data is encoded in a message format that contains all of the details needed to unseal it,
whether that means decryption, signature verification, sender identity validation, etc. excepting,
of course, any secrets needed to perform the unsealing operation.  The default message format uses
the [COSE](https://datatracker.ietf.org/doc/html/rfc8152) IETF standard, but other formats can be
provided.

Sigalgry also provides a lower-level API that consists of a set of abstract interfaces to common
cryptographic constructions.  This API is intended for use by experts in cryptographic security, and
uses normal industry terminology and structure.

## Sigaldry isolation

The Sigaldry API can be used to perform cryptographic operations in-process, meaning the library can
be linked into your application and all BindRunes will be managed/used within your own memory space,
but it's better to use it as an interface to an isolated Sigaldry environment to ensure that even if
your application is compromised, the attacker cannot extract the secrets without also compromising
the isolated environment.  Of course, an attacker who compromises your application can still use the
secrets in the same way your application can use them; this risk is unavoidable, but can be
partially mitigated by carefully restricting the ways in which Sigaldry will allow the secrets to be
used.

Sigaldry environments can provide various levels of isolation including:

* `SameProcess`:  This means "not isolated", i.e. running in the application's process space.
* `SeparateProcess`:  Sigaldry secret storage and operations run in another process in the same
  operating system as the application process.
* `VirtualMachine`:  Sigaldry secret storage and operations run in a virtual machine that is
  isolated from the application such that a full compromise of the OS under which the application is
  running is insufficient to compromise the secrets or operations.  Because the application and
  Sigaldry environment are running on the same CPU it's still possible for information to leak from
  the Sigaldry environment, for example through cache timings.
* `DiscreteCpu`:  Sigaldry secret storage and operations run on a separate CPU, preventing side
  channel leakage to an attacker who has compromised the application or OS it's running on.
  Hardware side channels or security deficincies of the discrete CPU may still enable attacks.
  Certified hardware may protect against such weaknesss; see the `Certification` Rune.

Isolation levels may be requested with the `Isolated` Rune.

[^sigaldry_name] The name "Sigaldry" is found in a few Middle English texts, from the 13th to 15th
centuries.  According to the Oxford English Dictionary it means "Enchantment" or "sorcery".  In its
original usage it seems to have had some secrecy-related overtones.  J.R.R. Tolkien used the word in
a few poems, bringing the word somewhat back into current use, and adding some association with
runic inscriptions.  Patrick Rothfuss used the word in his "Kingkiller Chronicle" to denote a form
of magic that adds mystical properties to objects by inscribing runes onto them.  The Sigaldry
library enables users to "inscribe" their data with protective "runes" that provide security
properties.  The API call to do this is called "seal" rather than "inscribe" because "uninscribe" is
an awkward term and it's nice to have symmetry between the names of the two operations.

[^bindrune_name] The name "BindRune" (Icelandic "bandrún") describes a ligature of Norse runes,
linking them together to form a symbol that combines their individual meanings and has magical
power.  In the case of Sigaldry a BindRune combines multiple Runes (security properties) with a
cryptographic key that has the power to provide those security properties.