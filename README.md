THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT THE AUTHORS BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# METACALLS -- Calling using derived identities

This project is inspired by https://forum.dfinity.org/t/icdevs-org-bounty-23b-metacalls-rust-up-to-10k/ post. As mentioned in that post, a canister has, by default, only one identity namely it's principal. Using t-ecsda, it is possible to create multiple derived identities for the same canister. Additionally it is possible to sign messsages using any one of the multiple derived entities; that can be verified. 

Currently it is possible to : 

```
 dfx canister call metacalls_backend list_messages
 --> ("")

 dfx canister call metacalls_backend list_derived_identities
 --> ("")
 ```


Then one create a default derived identity (aka root aka /). 

```
dfx canister call metacalls_backend create_derived_identity /
dfx canister call metacalls_backend list_derived_identities

--> ("/,")

dfx canister call metacalls_backend get_derived_identity /
--> (
  "PIdentity { key_name: \"/\", created_ts: 1672037770528881133, public_key: [3, 160, 144, 177, 117, 224, 24, 16, 10, 47, 253, 36, 97, 241, 126, 123, 179, 168, 69, 216, 35, 125, 11, 2, 22, 81, 110, 15, 15, 255, 104, 162, 153], chain_code: [14, 36, 113, 223, 4, 223, 30, 233, 84, 18, 245, 239, 188, 169, 101, 252, 75, 203, 97, 0, 116, 130, 121, 78, 115, 78, 105, 44, 174, 47, 111, 222] }",
)

```

Then one can create and sign messages

```
dfx canister call metacalls_backend create_message "Hello world"
--> ("5EC52E6D9D0A1349C5EAD8BDD69C438EE9570BBC79231A0CCE35B1F33F76AB96")


dfx canister call metacalls_backend list_messages 
--> (
  "Message { uuid: \"5EC52E6D9D0A1349C5EAD8BDD69C438EE9570BBC79231A0CCE35B1F33F76AB96\", created_ts: 1672038035331483194, last_updated_ts: 1672038035331483194, status: Created, original_message: \"Hello world\", hashed_message: [100, 236, 136, 202, 0, 178, 104, 229, 186, 26, 53, 103, 138, 27, 83, 22, 210, 18, 244, 243, 102, 178, 71, 114, 50, 83, 74, 138, 236, 163, 127, 60], signed_by: \"/\", signature: [] }, ",
)

```
Notice no signature, yet. 

```
 dfx canister call metacalls_backend sign_message 5EC52E6D9D0A1349C5EAD8BDD69C438EE9570BBC79231A0CCE35B1F33F76AB96

--> ("ok")

```

And we have a signature!
```
 dfx canister call metacalls_backend sign_message 5EC52E6D9D0A1349C5EAD8BDD69C438EE9570BBC79231A0CCE35B1F33F76AB96 
--> (
  "Message { uuid: \"5EC52E6D9D0A1349C5EAD8BDD69C438EE9570BBC79231A0CCE35B1F33F76AB96\", created_ts: 1672038035331483194, last_updated_ts: 1672038213649756290, status: Signed, original_message: \"Hello world\", hashed_message: [100, 236, 136, 202, 0, 178, 104, 229, 186, 26, 53, 103, 138, 27, 83, 22, 210, 18, 244, 243, 102, 178, 71, 114, 50, 83, 74, 138, 236, 163, 127, 60], signed_by: \"/\", signature: [131, 174, 29, 130, 184, 16, 79, 38, 38, 120, 186, 25, 45, 155, 143, 93, 128, 189, 112, 171, 203, 81, 32, 159, 46, 127, 118, 163, 229, 148, 186, 56, 95, 197, 242, 125, 135, 93, 84, 201, 100, 19, 30, 49, 247, 142, 168, 81, 130, 197, 223, 11, 40, 166, 86, 133, 167, 185, 32, 77, 87, 4, 125, 198] }, ",
)

```
## DOS 
Limited defensive denial of service capabilities provided through dos. 

## 1
The function "create_signed_message" creates a message and submits it for automatic signing. 

## 2
The function "create_message_for" is similar to create_message; except that it creates a message for a specific identity (i.e /finance/user/alice) for signature. The sign_message assumes the identity of /finance/user/alice).

## 3
The function "create_signed_message_with" is similar to create_signed_message; except that it creates a message and submits it for automatic signing with the specific derived identity (i.e. /engg/user/bob)

## 4 
The function "mc_set_timer_interval" sets the timing interval in seconds for message_queue to be checked for pruning. Initially 10 secs

## 5 
The function "mc_set_time_to_archive_message" sets the time from the create_date that the messages will be pruneds in ns. Initially 10000000000 ns



