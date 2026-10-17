package hostname

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// A registration selects one process birth on one boot/PID namespace, rather
// than letting service restarts reinterpret a persistent numeric PID.
type registeredTarget struct {
	Boot              string
	PIDNS, Dev, Inode uint64
}

type observerRegistration struct {
	Version int
	Config  ObserverConfig
	Target  registeredTarget
}

func targetIdentity(fd int) (registeredTarget, error) {
	boot, ns, err := ownerEnvironment()
	if err != nil {
		return registeredTarget{}, err
	}
	var fs unix.Statfs_t
	var stat unix.Stat_t
	if err := unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.PID_FS_MAGIC {
		return registeredTarget{}, errors.New("target requires a pidfs pidfd")
	}
	if err := unix.Fstat(fd, &stat); err != nil {
		return registeredTarget{}, err
	}
	if err := pidfdAlive(fd); err != nil {
		return registeredTarget{}, err
	}
	return registeredTarget{boot, ns, stat.Dev, stat.Ino}, nil
}

// PrepareObserver validates the explicit target and libraries without loading
// BPF, then atomically writes a root-private, boot-bound service registration.
func PrepareObserver(path string, config ObserverConfig) error {
	if err := config.validate(); err != nil {
		return err
	}
	if err := canonicalPath("registration", path); err != nil {
		return err
	}
	if err := trustedBootstrapPath(filepath.Dir(path), false); err != nil {
		return err
	}
	target, err := unix.PidfdOpen(config.TargetPID, 0)
	if err != nil {
		return err
	}
	defer unix.Close(target)
	identity, err := targetIdentity(target)
	if err != nil {
		return err
	}
	if err := targetInCgroup(config.TargetPID, config.Cgroup); err != nil {
		return err
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", config.TargetPID))
	if err != nil {
		return err
	}
	libs := []struct{ path, hash string }{{config.SSL, sslSHA256}, {config.Crypto, cryptoSHA256}, {config.C, libcSHA256}}
	if config.Curl != "" {
		libs = append(libs, struct{ path, hash string }{config.Curl, curlSHA256})
	}
	for _, lib := range libs {
		id, err := checkBinary(lib.path, lib.hash)
		if err != nil {
			return err
		}
		if _, err := mappingBase(string(maps), lib.path, id); err != nil {
			return err
		}
	}
	if err := pidfdAlive(target); err != nil {
		return err
	}
	if err := rootDirectory(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := trustedBootstrapPath(path, false); err != nil {
		return err
	}
	if old, err := secureOwnerFile(path, unix.O_RDONLY); err == nil {
		old.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".target-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(file).Encode(observerRegistration{1, config, identity}); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncOwnerDirectory(filepath.Dir(path))
}

func loadRegistration(path string) (observerRegistration, error) {
	var reg observerRegistration
	if err := trustedBootstrapPath(path, false); err != nil {
		return reg, err
	}
	file, err := secureOwnerFile(path, unix.O_RDONLY)
	if err != nil {
		return reg, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.Size() > 16384 {
		return reg, errors.New("invalid observer registration size")
	}
	dec := json.NewDecoder(io.LimitReader(file, 16385))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		return reg, errors.New("invalid observer registration")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return reg, errors.New("trailing observer registration data")
	}
	if reg.Version != 1 || reg.Target.Boot == "" || reg.Target.PIDNS == 0 || reg.Target.Inode == 0 {
		return reg, errors.New("incompatible observer registration")
	}
	return reg, reg.Config.validate()
}

// RegisteredPaths returns the runtime and pin directories recorded for a
// registered observer, so cleanup after its failure needs no matching flags.
func RegisteredPaths(path string) (runtime, pins string, err error) {
	reg, err := loadRegistration(path)
	if err != nil {
		return "", "", err
	}
	return reg.Config.Runtime, reg.Config.Pins, nil
}

// RunRegisteredObserver refuses stale registrations before attaching anything.
// A new target, boot or PID namespace requires an explicit new PrepareObserver.
func RunRegisteredObserver(ctx context.Context, path string, ready func()) error {
	reg, err := loadRegistration(path)
	if err != nil {
		return err
	}
	return runObserver(ctx, reg.Config, &reg.Target, ready)
}
