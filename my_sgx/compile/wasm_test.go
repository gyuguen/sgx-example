package compile_test

import (
	"fmt"
	"github.com/wasmerio/wasmer-go/wasmer"
	"io/ioutil"
	"testing"
)

func TestCompile(t *testing.T) {
	wasmBytes, err := ioutil.ReadFile("/mnt/c/Users/JGG/workspace/sgx/sgx-example/my_rust_sgx/target/wasm32-unknown-unknown/release/deps/my_rust_sgx.wasm")

	if err != nil {
		panic(err)
	}

	if len(wasmBytes) == 0 {
		panic("error!")
	}

	fmt.Println("1")
	engine := wasmer.NewEngine()

	store := wasmer.NewStore(engine)

	err = wasmer.ValidateModule(store, wasmBytes)

	fmt.Println("2")
	if err != nil {
		panic(err)
	}

	module, err := wasmer.NewModule(store, wasmBytes)

	fmt.Println("3")
	if err != nil {
		panic(err)
	}

	importObject := wasmer.NewImportObject()

	instance, err := wasmer.NewInstance(module, importObject)

	fmt.Println("4")
	if err != nil {
		panic(err)
	}

	fmt.Println("5")
	getRand, err := instance.Exports.GetFunction("get_rand")

	fmt.Println("6")
	if err != nil {
		panic(err)
	}

	result, err := getRand()

	fmt.Println("7")
	if err != nil {
		panic(err)
	}

	fmt.Println(result)
}
