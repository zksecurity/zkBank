# zkBank

**warning: please do not publish a write up or solution to this challenge, as we actively use it for recruiting :) thanks!**

Alice is a sneaky one, she's been trying to send more than what she has to Bob's account. Good thing that we use zero-knowledge proof to enforce the integrity of our transfer. We just want to make sure that Bob can get 100,000 worth of coins or more. Can you help us verify Alice's proof?

![zkbank](https://i.imgur.com/N6zakZ8.png)

## Setup

We assume that you have [Golang](https://go.dev/) installed. You can install the dependencies and run the tests:

```shell
$ go get -d ./...
$ go test
```

The test should fail as Bob did not get more than 100,000 coins in his account.

## Submitting a response

You can try submitting a proof on our servers here:

```shell
$ curl -X GET http://147.182.233.80:8080/ -H "Content-Type: application/json" -d '{ "new_bob_balance": "1000000", "proof_hex": "<HEX>" }'
```

You will get a congratulation message as well as next steps on how to apply if you succeed. Good luck :)
