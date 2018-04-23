docker for SIP Sysrepo plugin.

## build dockerfile

```
$ docker build -t sysrepo/sysrepo-netopeer2:provisioning -f Dockerfile .
```

## run dockerfile with supervisor

```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -i -t -v /opt/yang:/opt/fork --name provisioning -p 830:830 --rm sysrepo/sysrepo-netopeer2:provisioning
```

## run dockerfile without supervisor

```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -i -t -v /opt/yang:/opt/fork --name provisioning --rm sysrepo/sysrepo-netopeer2:provisioning bash
$ ubusd &
$ rpcd &
$ sysrepod
$ sysrepo-plugind
$ netopeer2-server
```
