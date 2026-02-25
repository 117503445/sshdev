package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <command>")
		fmt.Println("Commands: build, release, build-docker")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "build":
		build()
	case "release":
		release()
	case "build-docker":
		buildDocker()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func build() {
	fmt.Println("Building dev-sshd...")

	cmd := exec.Command("go", "build", "-ldflags", "-s -w", "-o", "./data/cli/dev-sshd", "./cmd/dev-sshd")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Build failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Build successful!")
}

func release() {
	fmt.Println("Building release binaries...")

	platforms := []string{
		"linux/amd64",
		"darwin/amd64",
		"darwin/arm64",
		"windows/amd64",
	}

	for _, platform := range platforms {
		parts := strings.Split(platform, "/")
		goos := parts[0]
		goarch := parts[1]

		binaryName := fmt.Sprintf("./data/release/dev-sshd-%s-%s", goos, goarch)
		if goos == "windows" {
			binaryName += ".exe"
		}

		fmt.Printf("Building for %s/%s...\n", goos, goarch)

		env := append(os.Environ(),
			"GOOS="+goos,
			"GOARCH="+goarch,
		)

		if goos == "linux" {
			env = append(env, "CGO_ENABLED=0")
		}

		cmd := exec.Command("go", "build", "-ldflags", "-s -w", "-o", binaryName, "./cmd/dev-sshd")
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		if err != nil {
			fmt.Printf("Build failed for %s/%s: %v\n", goos, goarch, err)
			os.Exit(1)
		}
	}

	fmt.Println("Release build successful!")
}

func buildDocker() {
	fmt.Println("Building Docker image...")

	cmd := exec.Command("docker", "build", "-t", "dev-sshd:latest", ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Docker build failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Docker build successful!")
}