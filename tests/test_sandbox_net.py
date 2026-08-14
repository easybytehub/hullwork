"""The network one attempt gets, and the self-test that is not taken on trust (item 047).

Docker is stood in for here, because what these tests are about is the *argument lists* and the
*decisions* — that the cable is created before it is attached, that a failed probe stops the attempt
rather than warning about it, that teardown happens even when construction raised. Whether Docker
then behaves is not a thing a double can tell us, and it is verified by running it (spec M2 §4.4's
own reason: a firewall nobody probes is a firewall nobody has).

The one property a double *can* prove, and the one worth proving, is that a reachable-but-open
network is refused. That is a decision, and decisions are testable.
"""

from pathlib import Path

import pytest

from hullwork.sandbox.net import CABLE_IMAGE, CABLE_PORT, GATEWAY_IMAGE, Cable, EgressError

#: What the fake `docker` answers for each subcommand. `PROBE_OK`/`PROBE_BLOCKED` decide the two
#: self-test outcomes: the first probe (urllib, to the gateway) and the second (a socket to the
#: internet) are told apart by what the program contains.
_SHIM = """#!/bin/sh
echo "$@" >> "$HULLWORK_TEST_LOG"
case "$1" in
  # `create` (the volume's carrier) can be made to fail on request, which is how a daemon that went
  # away mid-attempt is reproduced — the branch item 095 fixes. It answers normally by default.
  create) echo containerid; exit "${HULLWORK_TEST_CREATE_RC:-0}" ;;
esac
case "$1 $2" in
  "network create") echo netid; exit 0 ;;
  "network connect") exit 0 ;;
  "network rm") exit 0 ;;
  # The subnet the gateway is told to trust, read as soon as the network exists (item 054).
  "network inspect") echo "172.30.0.0/16"; exit 0 ;;
esac
case "$1" in
  # What `_wait_until_listening` reads. `HULLWORK_TEST_LISTENING` lets a test say the gateway never
  # bound, which is a different failure from a network that does not carry.
  logs) echo "$HULLWORK_TEST_LISTENING"; exit 0 ;;
  rm) exit 0 ;;
esac
case "$1 $2" in
  "inspect -f") echo running; exit 0 ;;
esac
case "$1" in
  inspect) echo "172.30.0.5"; exit 0 ;;
esac
# The cable itself is started detached, and its own source contains `create_connection` — so this
# has to be matched before the probes, or starting the cable looks like the blocked probe.
case "$1 $2" in
  "run --detach") echo containerid; exit "$HULLWORK_TEST_RUN_RC" ;;
esac
case "$*" in
  *urllib*) exit "$HULLWORK_TEST_GATEWAY_RC" ;;
  *create_connection*) exit "$HULLWORK_TEST_BLOCKED_RC" ;;
esac
echo containerid
exit "$HULLWORK_TEST_RUN_RC"
"""


@pytest.fixture
def docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A `docker` that answers, and writes down every argument list it was given."""
    shim = tmp_path / "docker"
    shim.write_text(_SHIM, encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("HULLWORK_TEST_LOG", str(tmp_path / "argv.log"))
    monkeypatch.setenv("HULLWORK_TEST_RUN_RC", "0")
    monkeypatch.setenv("HULLWORK_TEST_LISTENING", "gateway listening on 8080")
    monkeypatch.setenv("HULLWORK_TEST_GATEWAY_RC", "0")
    monkeypatch.setenv("HULLWORK_TEST_BLOCKED_RC", "1")
    return shim


def _log(tmp_path: Path) -> list[str]:
    text = (tmp_path / "argv.log").read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line]


def test_the_sandbox_is_told_the_gateway_s_address(docker: Path, tmp_path: Path) -> None:
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t1",
    ) as cable:
        assert cable.url == f"http://172.30.0.5:{CABLE_PORT}"
        assert cable.network == "hullwork-attempt-t1"


def test_the_gateway_is_told_the_network_it_should_trust(
    docker: Path, tmp_path: Path
) -> None:
    """It cannot be told the sandbox's address: the sandbox starts after it.

    This used to assert two different addresses — the internal one the sandbox dialled and the
    bridge one a gateway on the host saw the cable arrive from. That second hop is gone with item
    054, and what replaces it is the network: created for one attempt, destroyed with it, holding
    exactly the two containers this dispatcher put there.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t10",
    ) as cable:
        assert cable.address == "172.30.0.5"

    run = next(line for line in _log(tmp_path) if line.startswith("run --detach"))
    assert "--allow-network 172.30.0.0/16" in run


def test_the_network_is_internal_and_the_gateway_is_on_both(
    docker: Path, tmp_path: Path
) -> None:
    """The two halves of the arrangement, each visible in one argument list.

    `--internal` is what removes the route to the internet. The gateway is started on `bridge` — so
    it can reach the model endpoint — and attached to the internal network afterwards, so the
    sandbox can reach *it*. The other way round gives a gateway that can be reached and cannot
    forward.

    This used to assert `--add-host host.docker.internal`, which existed to let the cable reach a
    gateway on the host. There is no such hop now (item 054).
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t2",
    ):
        pass

    lines = _log(tmp_path)
    # Item 125 added `--label`. Asserted as parts, and one part more than before: internal, named,
    # and carrying the instance that will be allowed to reap it.
    created = [line for line in lines if line.startswith("network create")]
    assert len(created) == 1
    assert "--internal" in created[0]
    assert "--label hullwork.instance=default" in created[0]
    assert created[0].endswith("hullwork-attempt-t2")
    run = next(line for line in lines if line.startswith("run --detach"))
    assert "--network bridge" in run
    # Attached to the internal network *after* starting on the bridge: the other order gives a
    # gateway that can be reached and cannot forward.
    assert lines.index(run) < next(
        i for i, line in enumerate(lines) if line.startswith("network connect")
    )


def test_the_cable_is_attached_only_after_it_can_forward(docker: Path, tmp_path: Path) -> None:
    """Started on the bridge, then joined to the internal network.

    The other order gives a container the sandbox can reach and that cannot reach the gateway —
    which would fail the self-test with a message about the wrong thing.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t3",
    ):
        pass

    lines = _log(tmp_path)
    started = next(i for i, line in enumerate(lines) if line.startswith("run --detach"))
    attached = next(i for i, line in enumerate(lines) if line.startswith("network connect"))
    assert started < attached


def test_the_credential_reaches_the_gateway_as_a_file_and_never_as_an_argument(
    docker: Path, tmp_path: Path
) -> None:
    """This asserted the cable held **no** credential, and item 054 made that false by design.

    The cable used to be a dumb wire to a gateway on the host. It is the gateway now, because a
    container on an `--internal` network cannot reach a listener on the host — so it holds the key.
    DR-0004's promise is unchanged and is the one worth asserting: the key is not in the *sandbox*,
    and this is a different container on a different network that the watched project's test command
    cannot reach except through the API it exposes. See DR-0004's second amendment.

    What is asserted instead is the narrowest form the key can arrive in: a mounted file, mode 600.
    Not an argument, which `ps` shows; not an environment variable, which `docker inspect` shows.

    **The `:ro` bind-mount spelling used to be asserted here, and item 089 is why it is not.** That
    string was the *mechanism*, and asserting it kept this test green on a dispatcher that could not
    serve the credential at all: from inside a container (item 082) the daemon resolves the host
    path against its own filesystem, finds nothing, and mounts an empty directory — the gateway
    reads an empty key and every phase gets a 401. A test that names the mechanism cannot notice
    the mechanism stopping working. What is named now is the property: the path the gateway is
    *told* to read, and that the key is nowhere `ps` or `docker inspect` would show it.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t4",
    ):
        pass

    gateway_run = next(line for line in _log(tmp_path) if line.startswith("run --detach"))
    assert "--env" not in gateway_run
    assert "a-key" not in gateway_run
    assert "--credential-file /run/hullwork/credential" in gateway_run, (
        "the gateway is told to read a file, whatever carries it there"
    )
    assert (tmp_path / "credential").read_text(encoding="utf-8") == "a-key"
    assert oct((tmp_path / "credential").stat().st_mode)[-3:] == "600"
    assert GATEWAY_IMAGE in gateway_run


def test_an_unreachable_gateway_stops_the_attempt(
    docker: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before the model is called, and loudly.

    An agent with no model produces nothing and cannot say why; the run has to end here rather
    than spend the item's one attempt discovering it.
    """
    monkeypatch.setenv("HULLWORK_TEST_GATEWAY_RC", "1")

    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t5",
    ) as cable, pytest.raises(EgressError) as err:
        cable.self_test()

    assert "cannot reach the gateway" in str(err.value)


def test_a_network_with_a_way_out_is_refused(
    docker: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The probe that must fail. If it succeeds, the sandbox is not a sandbox.

    This is the half that a green suite would otherwise let through: everything works, the agent
    fixes bugs, and the watched project's source can leave the machine.
    """
    monkeypatch.setenv("HULLWORK_TEST_BLOCKED_RC", "0")

    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t6",
    ) as cable, pytest.raises(EgressError) as err:
        cable.self_test()

    assert "not isolated" in str(err.value)


def test_both_probes_run_inside_the_attempt_s_own_network(docker: Path, tmp_path: Path) -> None:
    """A self-test on a different network proves something about a network nobody used.

    Identified by the image they run, not by `run --rm`. `run --rm` is how a *throwaway container*
    starts and the cable has more than one reason to start one — item 089 added a `chown` that is
    also `run --rm` — so counting those counted something other than probes, and the count was the
    assertion. Asserted both ways round now: every probe on the attempt's network, and nothing on
    the attempt's network that is not a probe.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t7",
    ) as cable:
        cable.self_test()

    throwaway = [line for line in _log(tmp_path) if line.startswith("run --rm")]
    probes = [line for line in throwaway if CABLE_IMAGE in line]
    assert len(probes) == 2, "one probe for the route out, one for the route to the gateway"
    assert all("--network hullwork-attempt-t7" in probe for probe in probes)
    assert not [
        line for line in throwaway
        if "--network hullwork-attempt-t7" in line and line not in probes
    ], "something other than a probe ran inside the attempt's network"


def test_everything_is_torn_down_even_when_construction_fails(
    docker: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half a network is worse than none: it leaks, or it gets reused and reported as working."""
    monkeypatch.setenv("HULLWORK_TEST_RUN_RC", "1")

    with pytest.raises(EgressError), Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t8",
    ):
        pass  # pragma: no cover - the cable never comes up

    lines = _log(tmp_path)
    # `-v` since item 244: what the gateway's image declared as a VOLUME goes with the container.
    assert any(line.startswith("rm -f -v hullwork-cable-t8") for line in lines)
    assert any(line.startswith("network rm hullwork-attempt-t8") for line in lines)


def test_the_teardown_can_be_asked_twice(docker: Path, tmp_path: Path) -> None:
    """`close` runs from `__exit__` and from the failure path, and cannot care which came first."""
    cable = Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t9",
    )
    cable.__enter__()
    cable.close()
    cable.close()

    with pytest.raises(EgressError):
        _ = cable.address


def test_two_attempts_do_not_share_a_network(docker: Path, tmp_path: Path) -> None:
    """One recording per attempt (DR-0002): a shared gateway would seal the wrong run."""
    first = Cable("https://api.example", "a-key", work_dir=tmp_path / "a", docker=str(docker))
    second = Cable("https://api.example", "a-key", work_dir=tmp_path / "b", docker=str(docker))

    assert first.network != second.network
    assert first.container != second.container


def test_the_gateway_does_not_inherit_the_receivers_healthcheck(
    docker: Path, tmp_path: Path
) -> None:
    """**Item 087, measured on the live instance during a real attempt.**

    The gateway runs from Hullwork's own image, which carries a `HEALTHCHECK` probing
    `127.0.0.1:8000/ready` — right for the receiver, meaningless here: this container serves a
    forwarder on another port and no such route. It sat `unhealthy` with a 28-failure streak while
    answering the model with a clean 200 every few seconds.

    An `unhealthy` that only means "this is a different program" says nothing on the day the gateway
    really breaks. Same argument as `/health` cannot fail, from the other end.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t9",
    ):
        pass

    gateway_run = next(line for line in _log(tmp_path) if line.startswith("run --detach"))
    assert "--no-healthcheck" in gateway_run


# --- the credential in and the journal out travel through the socket. Item 089 -------------------


def test_no_host_path_is_bind_mounted_into_the_gateway(docker: Path, tmp_path: Path) -> None:
    """**The defect, and the reason the dispatcher had to stay on the host.**

    Item 082 put the dispatcher in a container, and this is what stopped it being deployed: the
    credential and the journal were bind mounts of paths under the dispatcher's own filesystem. A
    bind mount is resolved *by the daemon*, so the daemon looked for `/data/attempts/…/credential`
    among its own files, found nothing, and created an empty directory there — the gateway read an
    empty key (401 on every phase) and appended its journal to a file nobody would ever read,
    publishing a seal that says the model was never reached on a run where it answered twice.

    Asserted as an absence, because the failure was an absence: any argument mounting a path from
    this process's filesystem. `tmp_path` is that filesystem here, which is what makes it checkable.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t11",
    ):
        pass

    gateway_run = next(line for line in _log(tmp_path) if line.startswith("run --detach"))
    mounts = [
        argument for argument in gateway_run.split()
        if ":" in argument and argument.startswith("/")
    ]
    assert mounts == [], f"a host path is bind mounted into the gateway: {mounts}"
    assert str(tmp_path) not in gateway_run, (
        "the dispatcher's own filesystem is named in the gateway's arguments, and the daemon does "
        "not share it"
    )
    assert "--volume hullwork-wire-t11:/run/hullwork" in gateway_run


def test_the_volume_is_seeded_through_the_socket_and_given_to_the_user_that_runs(
    docker: Path, tmp_path: Path
) -> None:
    """`docker cp` streams a tar; that is the whole difference from a bind mount.

    And the ownership half: a volume seeded through the socket arrives owned by root, so without the
    `chown` the gateway — which runs as this process's uid, not root — cannot read a mode-600 file
    it is pointed at, nor append to the journal beside it. Measured as the second half of the same
    failure in item 055.
    """
    import os

    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t12",
    ):
        pass

    lines = _log(tmp_path)
    # Item 125: the volume that carries the model credential is the one it matters most to label,
    # because it is the one another instance's reaper would have removed.
    made = [line for line in lines if line.startswith("volume create")]
    assert any(
        "--label hullwork.instance=default" in line and line.endswith("hullwork-wire-t12")
        for line in made
    )
    copied = [line for line in lines if line.startswith("cp ")]
    assert any("credential" in line and "/run/hullwork/credential" in line for line in copied), (
        "the credential must be copied in, not mounted"
    )
    assert any("journal.jsonl" in line for line in copied)
    chowned = next(line for line in lines if "chown" in line)
    assert f"chown -R {os.getuid()}:{os.getgid()} /run/hullwork" in chowned
    # In a carrier that mounts the volume — not by reaching into the daemon's filesystem.
    assert "--volume hullwork-wire-t12:/run/hullwork" in chowned


def test_the_journal_is_fetched_before_the_seal_is_read(docker: Path, tmp_path: Path) -> None:
    """The gateway appends inside the volume, so the host copy is stale until it is fetched.

    Without the pull, `recording` reads the empty file this process touched at start-up and the seal
    reports a run nobody observed — the same lie as the empty credential, one step further along and
    harder to notice, because an attempt with an empty seal still finishes.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t13",
    ) as cable:
        before = len([line for line in _log(tmp_path) if line.startswith("cp ")])
        cable.recording("https://api.example")
        after = [line for line in _log(tmp_path) if line.startswith("cp ")]

    assert len(after) > before, "the seal was read without fetching the journal first"
    assert "hullwork-wire-t13" in next(
        line for line in _log(tmp_path) if line.startswith("create --volume")
    )
    assert any(
        line.startswith("cp ") and "/run/hullwork/journal.jsonl" in line
        and line.rstrip().endswith(str(tmp_path / "journal.jsonl"))
        for line in after
    ), "the journal must come *out* of the volume, into the path `recording` reads"


def test_the_volume_goes_with_the_attempt(docker: Path, tmp_path: Path) -> None:
    """A volume per attempt that outlives it is a disk that fills, holding a credential each time.

    And the journal is fetched one last time before it goes: an attempt that died before anything
    asked for its seal is exactly the one worth reading afterwards.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t14",
    ):
        pass

    lines = _log(tmp_path)
    removed = next(i for i, line in enumerate(lines) if line == "volume rm -f hullwork-wire-t14")
    # By **direction**, not by the two words both directions share. The seeding copy also names
    # `journal.jsonl` and the host path — it just names them the other way round — so a filter that
    # matched both stayed green with the fetch deleted. Caught by reintroducing exactly that.
    pulled = [
        i for i, line in enumerate(lines)
        if line.startswith("cp ") and line.rstrip().endswith(str(tmp_path / "journal.jsonl"))
    ]
    assert pulled, "the journal was never fetched out of the volume"
    assert min(pulled) < removed, "the volume was removed before the journal was read back"


# --- teardown completes even when the daemon has gone away. Item 095 ------------------------------


def test_teardown_completes_when_the_journal_cannot_be_fetched(
    docker: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The follow-up the agent filed in `!10` and deliberately did not take.**

    `_pull_journal`'s docstring promised "logged and swallowed, never raised" over a `_carrier`
    that raises `EgressError` on a failed `docker create`. From `close` it is the *first* call,
    so a daemon that had gone away aborted teardown before `rm -f`, `network rm` and `volume rm
    -f` — leaking a network, a container, and a volume holding a copy of the model credential.

    Worse than the one that was fixed in that pull request: that path was reached with nothing
    created yet, and this one is reached from `__exit__` after a successful run, when all three
    exist.

    Driven through a **failing `docker create`** rather than a missing binary, because the missing
    binary is the case the agent's own test already covered and this is the branch it could not
    reach.
    """
    with Cable(
        "https://api.example", "a-key", work_dir=tmp_path,
        docker=str(docker), suffix="t15",
    ) as cable:
        cable.recording("https://api.example")  # a journal exists, so the pull is attempted
        # From here on `docker create` fails, which is how a daemon that has gone away looks to the
        # carrier. Everything else the shim answers unchanged.
        monkeypatch.setenv("HULLWORK_TEST_CREATE_RC", "1")

    lines = _log(tmp_path)
    # Teardown ran to the end: all three removals happened despite the journal being unreadable.
    # `-v` since item 244: the gateway's own anonymous volumes go with it, and a removal without
    # it left 69 of them on the operator's host in a day.
    assert any(line.startswith("rm -f -v hullwork-cable-t15") for line in lines), (
        f"the container was not removed: {lines}"
    )
    assert any(line == "network rm hullwork-attempt-t15" for line in lines), (
        f"the network was left on the host: {lines}"
    )
    assert any(line == "volume rm -f hullwork-wire-t15" for line in lines), (
        f"the volume was leaked, and it holds a copy of the model credential: {lines}"
    )
