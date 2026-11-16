"""Configuration persistante des interfaces invitées par backend confirmé."""

from __future__ import annotations

import base64
import shlex
from ipaddress import ip_interface

import yaml

from .guest_control import GuestCommandPlan, GuestControlError, GuestControlService
from .models import GuestNetworkBackend, InterfacePurpose, MachineInterface, OSFamily, Scenario


class GuestNetworkService:
    """Produit les scripts exacts sans choisir implicitement un gestionnaire réseau."""

    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.control = GuestControlService(scenario)

    def build_plans(self) -> list[GuestCommandPlan]:
        """Construit un plan par VM à partir des interfaces du modèle canonique."""

        plans: list[GuestCommandPlan] = []
        for machine in [*self.scenario.infrastructure, *self.scenario.targets]:
            interfaces = [
                interface
                for interface in machine.interfaces
                if interface.purpose != InterfacePurpose.MANAGEMENT
            ]
            if machine in self.scenario.infrastructure:
                interfaces.extend(
                    interface
                    for interface in machine.interfaces
                    if interface.purpose == InterfacePurpose.MANAGEMENT
                )
            # La carte d'amorçage des cibles reste en DHCP jusqu'à son
            # isolation. Elle sert de transport au provisionnement, mais n'est
            # jamais transformée en carte VMnet0 ni configurée comme interface
            # permanente par ce module.
            if not interfaces:
                continue
            if machine.network_backend is None:
                raise GuestControlError(
                    f"Backend réseau invité non confirmé pour {machine.id}"
                )
            endpoint = self.control.endpoint(machine.id)
            self._validate_backend(machine.id, endpoint.os_family, machine.network_backend)
            if machine.network_backend == GuestNetworkBackend.WINDOWS_POWERSHELL:
                command = self._windows_script(interfaces)
            elif machine.network_backend == GuestNetworkBackend.LINUX_NMCLI:
                command = self._nmcli_script(interfaces)
            else:
                command = self._netplan_script(machine.id, interfaces)
            plans.append(
                GuestCommandPlan(
                    action="configure_guest_network",
                    machine_id=machine.id,
                    transport=endpoint.access.communicator,
                    address=endpoint.address,
                    remote_command=command,
                    description=f"Configurer {len(interfaces)} interface(s) par {machine.network_backend.value}",
                )
            )
        return plans

    @staticmethod
    def _validate_backend(machine_id: str, os_family: OSFamily, backend: GuestNetworkBackend) -> None:
        windows = backend == GuestNetworkBackend.WINDOWS_POWERSHELL
        if windows != (os_family == OSFamily.WINDOWS):
            raise GuestControlError(
                f"Le backend {backend.value} ne correspond pas à l'OS de {machine_id}"
            )

    @staticmethod
    def _windows_script(interfaces) -> str:
        lines = ["$ErrorActionPreference='Stop'"]
        for interface in interfaces:
            identity = GuestNetworkService._windows_adapter_lookup(interface)
            parsed = ip_interface(interface.address)
            lines.extend(
                [
                    f"$adapter={identity}",
                    "if(@($adapter).Count -ne 1){throw 'Interface VMware ambiguë ou introuvable'}",
                    "$old=Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue",
                    "$old | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue",
                    (
                        "New-NetIPAddress -InterfaceIndex $adapter.ifIndex "
                        f"-IPAddress '{parsed.ip}' -PrefixLength {parsed.network.prefixlen}"
                        + (f" -DefaultGateway '{interface.gateway}'" if interface.gateway else "")
                    ),
                ]
            )
            if interface.disable_dns:
                # Cette combinaison désactive l'enregistrement DNS et retire les
                # serveurs explicites; elle reste visible dans le plan à valider.
                lines.extend(
                    [
                        "Set-DnsClient -InterfaceIndex $adapter.ifIndex -RegisterThisConnectionsAddress $false",
                        "Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses",
                    ]
                )
        return "; ".join(lines)

    @staticmethod
    def _windows_adapter_lookup(interface) -> str:
        if interface.mac:
            normalized = interface.mac.replace(":", "-").upper().replace("'", "''")
            return f"Get-NetAdapter | Where-Object {{$_.MacAddress -eq '{normalized}'}}"
        if interface.name:
            escaped = interface.name.replace("'", "''")
            return f"Get-NetAdapter -Name '{escaped}' -ErrorAction Stop"
        raise GuestControlError("Une interface Windows exige une MAC ou un nom invité")

    @staticmethod
    def _nmcli_script(interfaces) -> str:
        commands = ["set -eu"]
        for interface in interfaces:
            if not interface.name:
                raise GuestControlError("Une interface NetworkManager exige son nom invité")
            name = shlex.quote(interface.name)
            address = shlex.quote(interface.address)
            commands.extend(
                [
                    f"connection=$(nmcli -g GENERAL.CONNECTION device show {name})",
                    "test -n \"$connection\" -a \"$connection\" != '--'",
                    f"sudo -n nmcli connection modify \"$connection\" ipv4.method manual ipv4.addresses {address}",
                ]
            )
            if interface.gateway:
                commands.append(
                    f"sudo -n nmcli connection modify \"$connection\" ipv4.gateway {shlex.quote(interface.gateway)}"
                )
            if interface.disable_dns:
                commands.append(
                    "sudo -n nmcli connection modify \"$connection\" ipv4.ignore-auto-dns yes ipv4.dns ''"
                )
            commands.append("sudo -n nmcli connection up \"$connection\"")
        return "; ".join(commands)

    @staticmethod
    def _netplan_script(machine_id: str, interfaces) -> str:
        ethernets = {}
        for index, interface in enumerate(interfaces):
            key = f"cygil{index}"
            body: dict = {"addresses": [interface.address], "dhcp4": False}
            if interface.mac:
                body["match"] = {"macaddress": interface.mac.lower()}
                if interface.name:
                    body["set-name"] = interface.name
            elif interface.name:
                key = interface.name
            else:
                raise GuestControlError("Netplan exige une MAC ou un nom d'interface")
            if interface.gateway:
                body["routes"] = [{"to": "default", "via": interface.gateway}]
            ethernets[key] = body
        document = {"network": {"version": 2, "ethernets": ethernets}}
        encoded = base64.b64encode(
            yaml.safe_dump(document, sort_keys=False).encode("utf-8")
        ).decode("ascii")
        safe_id = "".join(character for character in machine_id if character.isalnum() or character in "-_")
        destination = f"/etc/netplan/99-cygil-{safe_id}.yaml"
        return (
            f"echo {encoded} | base64 --decode | sudo -n tee {shlex.quote(destination)} >/dev/null; "
            "sudo -n netplan generate; sudo -n netplan apply"
        )
