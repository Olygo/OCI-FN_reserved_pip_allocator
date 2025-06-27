############################################################################################
#   OCI-FN_reserved_pip_allocator                                                           #
#   Florian Bonneville                                                                      #
#   2025-06-26                                                                              #
#   1.0.0                                                                                   #
#                                                                                           #
#   Call this function via the 'Instance - Launch End' notification.                        #
#   It analyzes the compute instance and assigns a reserved public IP.                      #
#   If no reserved public IP is available, one will be automatically created and assigned.  #
#############################################################################################

import io
import os
import json
import oci
import time
import uuid
import logging
from fdk import response

def configure_logger(name=__name__, log_level=logging.INFO, include_level=True, include_module=False):

    # levels of severity
        # DEBUG     -> All levels (very verbose)        ->  everything happening inside OCI SDK
        # INFO      -> INFO, WARNING, ERROR, CRITICAL)  ->  For detailed logs about retries, API calls, backoff
        # WARNING   -> WARNING, ERROR, CRITICAL)        ->  only warnings about retry attempts or circuit breaker tripping
        # ERROR     -> ERROR, CRITICAL)                 ->  only serious problems (network failures, unhandled exceptions)
        # CRITICAL  -> CRITICAL only)                   ->  Log only fatal internal errors
        # NOTSET    -> Respects parent logger's level)  ->  Inherit from root logger

    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        format_elements = []
        if include_level:
            format_elements.append('%(levelname)s')
        if include_module:
            format_elements.append('%(module)s')
        format_elements.append('%(message)s')
        formatter = logging.Formatter(' - '.join(format_elements))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # prevents the logger from propagating logs to the parent logger (e.g. root)
    logger.propagate = False

    return logger

def set_log_header(ctx):

    # thanks to log_header, you can easily identify logs from different requests, 
    # even when the function is called simultaneously by multiple instances
    # you can add your own log_header using function configuration key/value, 
    # here the required key is 'log_header'

    # generate a log uuid (4*char)
    log_uuid = f"{uuid.uuid4().hex[:4]}"

    # fetch log_header from function context, if any
    log_header=ctx.Config().get("log_header", "")
    log_header=f"{log_header}_{log_uuid}" if log_header else f"FN_{log_uuid}"
    
    return log_header

def get_instance_details(log_header, compute_client, instance_id):

    try:
        instance_details=compute_client.get_instance(instance_id=instance_id).data
        return instance_details
    
    except Exception as e:
        log_critical(f"{log_header}: An error occured in: --get_instance_details-- :{e}")
        raise

def get_vnic(log_header, network_client, compute_client, instance_id, compartment_id):

    try:
        vnic_attachments=compute_client.list_vnic_attachments(
                compartment_id=compartment_id,
                instance_id=instance_id).data
        for vnic in vnic_attachments:
            # retrieve only the first vnic
            if vnic.nic_index == 0:
                return (vnic)

    except Exception as e:
        log_critical(f"{log_header}: An error occured in: --get_vnic-- :{e}")
        raise

def list_private_ips(log_header, network_client, subnet_id, vnic_id):

    try:
        list_private_ips = network_client.list_private_ips(
            subnet_id=subnet_id,
            vnic_id=vnic_id
            )
        log_info(f"{log_header}: {list_private_ips.data[0].lifetime} private Ip: {list_private_ips.data[0].ip_address} found")
        #log_info(f"{log_header}: Private Ip is_primary: {list_private_ips.data[0].is_primary}")
        return list_private_ips.data[0]

    except Exception as e:
        log_critical(f"{log_header}: An error occured in: --list_private_ips-- :{e}")
        raise

def list_public_ips(log_header, network_client, scope="", compartment_id="", lifetime="", availability_domain="", public_ip=""):

    try:
        if scope == "REGION":
            # check if reserved public ips exist and available
            public_ips = network_client.list_public_ips(
                scope=scope,
                compartment_id=compartment_id,
                lifetime=lifetime
            ).data
            return [pip for pip in public_ips if pip.lifecycle_state == "AVAILABLE"]

        else:
            # search for the instance ephemeral public ip
            public_ips = network_client.list_public_ips(
                scope=scope,
                compartment_id=compartment_id,
                availability_domain=availability_domain,
                lifetime=lifetime
            ).data

            for pip in public_ips:
                if pip.ip_address == public_ip:
                    log_info(f"{log_header}: Public IP: {pip.ip_address} is {pip.lifetime}")
                    return pip
            return None

    except Exception as e:
        log_critical(f"{log_header}: An error occured in: --list_public_ips-- :{e}")
        raise

def check_public_ip_lifetime(log_header, network_client, public_ip):

    try:
        response = network_client.get_public_ip_by_ip_address(
            get_public_ip_by_ip_address_details=oci.core.models.GetPublicIpByIpAddressDetails(
                ip_address=public_ip
            )
        )

        ip_data = response.data
        log_info(f"{log_header}: Assigned public IP {ip_data.ip_address} is {ip_data.lifetime}")

        if ip_data.lifetime == "RESERVED":
            raise SystemExit(0)
        else:
            return ip_data

    except Exception as e:
        log_critical(f"{log_header}: An error occurred in --check_public_ip_lifetime-- : {e}")
        raise

def create_public_ip(log_header, network_client, compartment_id):
    
    try:
        create_public_ip = network_client.create_public_ip(
            create_public_ip_details=oci.core.models.CreatePublicIpDetails(
                compartment_id=compartment_id,
                lifetime="RESERVED"))
        log_info(f"{log_header}: Reserved public IP created: {create_public_ip.data.ip_address}")

        create_wait_response=oci.wait_until(
            network_client, 
            network_client.get_public_ip(public_ip_id=create_public_ip.data.id), 
            'lifecycle_state', 
            'AVAILABLE', 
            max_wait_seconds=120
            ).data

        # update available_public_ips list to include ip newly created
        available_public_ips = list_public_ips(
            log_header,
            network_client, 
            scope="REGION", 
            compartment_id=compartment_id,
            lifetime="RESERVED"
            )
        return available_public_ips    

    except Exception as e:
        log_critical(f"{log_header}: An error occurred in --create_public_ip--: {e}")
        raise

def delete_public_ip(log_header, network_client, public_ip_id, vnic_id):

    try:
        network_client.delete_public_ip(public_ip_id=public_ip_id)
        # check public ip has been removed 
        while True:
            vnic_details = network_client.get_vnic(vnic_id=vnic_id).data
            if not vnic_details.public_ip:
                log_info(f"{log_header}: Ephemeral public IP successfully removed")
                break
            else:
                log_info(f"{log_header}: Removing ephemeral public IP...")
                time.sleep(5)
        return

    except Exception as e:
        log_critical(f"{log_header}: An error occurred in --delete_public_ip--: {e}")
        raise

def assign_public_ip(log_header, network_client, public_ip_id, private_ip_id):
    
    try:
        update_public_ip=network_client.update_public_ip(
            public_ip_id=public_ip_id,
            update_public_ip_details=oci.core.models.UpdatePublicIpDetails(
                private_ip_id=private_ip_id
                )
            )
        log_info(f"{log_header}: Public IP {update_public_ip.data.ip_address} is {update_public_ip.data.lifecycle_state}")
        return

    except Exception as e:
        log_critical(f"{log_header}: An error occurred in --assign_public_ip-- : {e}")
        raise

##########################################################################
# main
##########################################################################

logger = configure_logger(log_level=logging.INFO)
log_info = logger.info
log_warning = logger.warning
log_error = logger.error
log_critical = logger.critical

# Set oci logging at Warning level
logging.getLogger('oci').setLevel(logging.WARNING)
# Set oci.circuit_breaker logging at Warning level
logging.getLogger('oci.circuit_breaker').setLevel(logging.WARNING)

def handler(ctx, data: io.BytesIO=None):
    signer = oci.auth.signers.get_resource_principals_signer()
    compute_client = oci.core.ComputeClient(config={}, signer=signer)
    network_client=oci.core.VirtualNetworkClient(config={}, signer=signer)
    log_header = set_log_header(ctx)

    try:
        body=json.loads(data.getvalue())
        resource_data = body["data"]
        # resource_compartment_name = body["data"]["compartmentName"]
        resource_compartment_id = body["data"]["compartmentId"]
        # resource_name = body["data"]["resourceName"]
        resource_ocid = body["data"]["resourceId"]
        # resource_ad = body["data"]["availabilityDomain"]
        # resource_shape = body["data"]["additionalDetails"]["shape"]
        # resource_imageId = body["data"]["additionalDetails"]["imageId"]
        # log_info(f"{log_header}: data: {resource_data}")
        # log_info(f"{log_header}: compartment_name: {resource_compartment_name}")
        # log_info(f"{log_header}: compartment_id: {resource_compartment_id}")
        # log_info(f"{log_header}: name: {resource_name}")
        # log_info(f"{log_header}: ocid: {resource_ocid}")
        # log_info(f"{log_header}: ad: {resource_ad}")
        # log_info(f"{log_header}: shape: {resource_shape}")
        # log_info(f"{log_header}: imageid: {resource_imageId}")
        
        if 'ocid1.instance.' in resource_ocid:
            instance_details = get_instance_details(log_header, compute_client, resource_ocid)
            instance_vnic = get_vnic(log_header, network_client, compute_client, resource_ocid, resource_compartment_id)
            vnic_details = network_client.get_vnic(vnic_id=instance_vnic.vnic_id).data

            log_info(f"{log_header}: Starting analysis for instance: {instance_details.display_name}")
            log_info(f"{log_header}: Checking for assigned public IP...")

            if vnic_details.public_ip:
                public_ip_data=check_public_ip_lifetime(log_header, network_client, vnic_details.public_ip)
                assigned_public_ip = True
            else:
                assigned_public_ip = False
                log_info(f"{log_header}: No public IP assigned")
                log_info(f"{log_header}: Checking if the subnet allows public IPs...")
                vnic_subnet = network_client.get_subnet(subnet_id=vnic_details.subnet_id)

                if vnic_subnet.data.prohibit_public_ip_on_vnic:
                    log_info(f"{log_header}: No: prohibit_public_ip_on_vnic: {vnic_subnet.data.prohibit_public_ip_on_vnic}")
                    raise SystemExit(0)
                else:
                    log_info(f"{log_header}: Yes: prohibit_public_ip_on_vnic: {vnic_subnet.data.prohibit_public_ip_on_vnic}")

            log_info(f"{log_header}: Fetching instance private IP...")
            private_ip=list_private_ips(
                log_header, 
                network_client, 
                instance_vnic.subnet_id, 
                instance_vnic.vnic_id
                )

            log_info(f"{log_header}: Fetching available reserved public IP(s)...")
            available_public_ips = list_public_ips(
                log_header, 
                network_client,
                scope="REGION",
                compartment_id=resource_compartment_id,
                lifetime="RESERVED"
                )

            if not available_public_ips :
                log_info(f"{log_header}: Found '{len(available_public_ips)}' available reserved public IP")
                log_info(f"{log_header}: Creating reserved public IP...")
                available_public_ips=create_public_ip(log_header, network_client,resource_compartment_id)

            else:
                log_info(f"{log_header}: Found '{len(available_public_ips)}' available reserved public IP(s)")

            if assigned_public_ip:
                if public_ip_data and public_ip_data.lifetime == "EPHEMERAL":
                    log_info(f"{log_header}: Removing ephemeral public IP: {public_ip_data.ip_address}...")
                    delete_public_ip(log_header, network_client, public_ip_data.id, instance_vnic.vnic_id)
                
            log_info(f"{log_header}: Assigning reserved public IP {available_public_ips[0].ip_address} to {instance_details.display_name}...")
            assign_public_ip(log_header, network_client, available_public_ips[0].id, private_ip.id)
        
        else:
            log_info(f"{log_header}: Resource is not a compute instance: {resource_ocid}")
            raise SystemExit(0)

    except Exception as e:
        log_critical(f"{log_header}: Handler failed: {e}")
        raise

    return response.Response(
        ctx,
        response_data=json.dumps(body),
        headers={"Content-Type": "application/json"}
    )