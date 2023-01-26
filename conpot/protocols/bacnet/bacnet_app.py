# Copyright (C) 2015  Peter Sooky <xsooky00@stud.fit.vubtr.cz>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Author: Peter Sooky <xsooky00@stud.fit.vubtr.cz>
# Brno University of Technology, Faculty of Information Technology

import logging
import re
import sys

from bacpypes.bvll import BVLPDU, OriginalUnicastNPDU, OriginalBroadcastNPDU
from bacpypes.errors import ExecutionError
from bacpypes.npdu import NPDU
from bacpypes.pdu import Address as PduAddress
from bacpypes.pdu import GlobalBroadcast
import bacpypes.object
from bacpypes.app import BIPSimpleApplication
from bacpypes.constructeddata import Any
from bacpypes.constructeddata import InvalidParameterDatatype
from bacpypes.apdu import (
    APDU,
    apdu_types,
    confirmed_request_types,
    unconfirmed_request_types,
    ErrorPDU,
    RejectPDU,
    IAmRequest,
    IHaveRequest,
    ReadPropertyACK,
    ConfirmedServiceChoice,
    UnconfirmedServiceChoice,
    Error,
    ReadPropertyMultipleACK,
    ReadAccessResult,
    ReadAccessResultElement,
    ReadAccessResultElementChoice
)
from bacpypes.pdu import PDU
from bacpypes.service import object as BacpypesServiceObject
from bacpypes.basetypes import ErrorType

logger = logging.getLogger(__name__)


class BACnetApp(BIPSimpleApplication):
    """
    BACnet device emulation class. BACnet properties are populated from the template file. Services are defined.
    Conpot implements a smart sensor and hence
    - DM-RP-B (execute ReadProperty)
    - DM-DDB-B (execute Who-Is, initiate I-Am)
    - DM-DOB-B (execute Who-Has, initiate I-Have)
    services are supported.
    """

    def __init__(self, device, datagram_server):
        self._request = None
        self._response = None
        self._response_service = None
        self.localDevice = device
        self.objectName = {device.objectName: device}
        self.objectIdentifier = {device.objectIdentifier: device}
        self.datagram_server = datagram_server
        self.deviceIdentifier = None
        super(BIPSimpleApplication, self).__init__()

    def get_objects_and_properties(self, dom):
        """
        parse the bacnet template for objects and their properties
        """
        self.deviceIdentifier = ("device", int(dom.xpath("//bacnet/device_info/*")[1].text))
        device_property_list = dom.xpath("//bacnet/device_info/*")
        for prop in device_property_list:
            prop_key = prop.tag.lower().title()
            prop_key = re.sub("['_','-']", "", prop_key)
            prop_key = prop_key[0].lower() + prop_key[1:]
            if (
                prop_key not in self.localDevice.propertyList.value
                and prop_key not in ["deviceIdentifier", "deviceName"]
            ):
                self.add_property(prop_key, prop.text)

        object_list = dom.xpath("//bacnet/object_list/object/@name")
        for obj in object_list:
            property_list = dom.xpath(
                '//bacnet/object_list/object[@name="%s"]/properties/*' % obj
            )
            for prop in property_list:
                if prop.tag == "object_type":
                    object_type = re.sub("-", " ", prop.text).lower().title()
                    object_type = re.sub(" ", "", object_type) + "Object"
            try:
                device_object = getattr(bacpypes.object, object_type)()
                device_object.propertyList = list()
            except NameError:
                logger.critical("Non-existent BACnet object type")
                sys.exit(3)
            for prop in property_list:
                prop_key = prop.tag.lower().title()
                prop_key = re.sub("['_','-']", "", prop_key)
                prop_key = prop_key[0].lower() + prop_key[1:]
                if prop_key == "objectType":
                    prop_val = prop.text.lower().title()
                    prop_val = re.sub(" ", "", prop_val)
                    prop_val = prop_val[0].lower() + prop_val[1:]
                elif prop_key == "presentValue":
                    try:
                        prop_val = float(prop.text)
                    except ValueError:
                        prop_val = prop.text
                else:
                    prop_val = prop.text
                try:
                    if prop_key == "objectIdentifier":
                        device_object.objectIdentifier = int(prop_val)
                    else:
                        setattr(device_object, prop_key, prop_val)
                        device_object.propertyList.append(prop_key)
                except bacpypes.object.PropertyError:
                    logger.critical("Non-existent BACnet property type")
                    sys.exit(3)
            self.add_object(device_object)

    def add_object(self, obj):
        object_name = obj.objectName
        if not object_name:
            raise RuntimeError("object name required")
        object_identifier = obj.objectIdentifier
        if not object_identifier:
            raise RuntimeError("object identifier required")
        if object_name in self.objectName:
            raise RuntimeError("object already added with the same name")
        if object_identifier in self.objectIdentifier:
            raise RuntimeError("object already added with the same identifier")

        # Keep dictionaries -- for name and identifiers
        self.objectName[object_name] = obj
        self.objectIdentifier[object_identifier] = obj
        self.localDevice.objectList.append(object_identifier)

    def add_property(self, prop_name, prop_value):
        if not prop_name:
            raise RuntimeError("property name required")
        if not prop_value:
            raise RuntimeError("property value required")

        setattr(self.localDevice, prop_name, prop_value)
        self.localDevice.propertyList.append(prop_name)

    def iAm(self, *args):
        self._response = None
        return

    def iHave(self, *args):
        self._response = None
        return

    def whoIs(self, request, address, invoke_key, device):
        # Limits are optional (but if used, must be paired)
        execute = False
        try:
            if (request.deviceInstanceRangeLowLimit is not None) and (
                request.deviceInstanceRangeHighLimit is not None
            ):
                if (
                    request.deviceInstanceRangeLowLimit
                    > list(self.objectIdentifier.keys())[0][1]
                    > request.deviceInstanceRangeHighLimit
                ):
                    logger.info("Bacnet WhoHasRequest out of range")
                else:
                    execute = True
            else:
                execute = True
        except AttributeError:
            execute = True

        if execute:
            self._response_service = "IAmRequest"
            self._response = IAmRequest()
            # todo make possible to use both GlobalBroadcast or Unicast address
            # self._response.pduDestination = GlobalBroadcast()
            self._response.pduDestination = PduAddress(address)
            self._response.iAmDeviceIdentifier = self.deviceIdentifier
            # self._response.objectIdentifier = list(self.objectIdentifier.keys())[0][1]
            self._response.maxAPDULengthAccepted = int(
                getattr(self.localDevice, "maxApduLengthAccepted")
            )
            self._response.segmentationSupported = getattr(
                self.localDevice, "segmentationSupported"
            )
            self._response.vendorID = int(getattr(self.localDevice, "vendorIdentifier"))

    def whoHas(self, request, address, invoke_key, device):
        execute = False
        try:
            if (request.deviceInstanceRangeLowLimit is not None) and (
                request.deviceInstanceRangeHighLimit is not None
            ):
                if (
                    request.deviceInstanceRangeLowLimit
                    > list(self.objectIdentifier.keys())[0][1]
                    > request.deviceInstanceRangeHighLimit
                ):
                    logger.info("Bacnet WhoHasRequest out of range")
                else:
                    execute = True
            else:
                execute = True
        except AttributeError:
            execute = True

        if execute:
            for obj in device.objectList.value[2:]:
                if (
                    int(request.object.objectIdentifier[1]) == obj[1]
                    and request.object.objectIdentifier[0] == obj[0]
                ):
                    objName = self.objectIdentifier[obj].objectName
                    self._response_service = "IHaveRequest"
                    self._response = IHaveRequest()
                    # todo make possible to use both GlobalBroadcast or Unicast address
                    # self._response.pduDestination = GlobalBroadcast()
                    self._response.pduDestination = PduAddress(address)
                    # self._response.deviceIdentifier = list(self.objectIdentifier.keys())[0][1]
                    self._response.deviceIdentifier = self.deviceIdentifier
                    self._response.objectIdentifier = obj[1]
                    self._response.objectName = objName
                    break
            else:
                logger.info("Bacnet WhoHasRequest: no object found")

    def readProperty(self, request, address, invoke_key, device):
        # Read Property
        # TODO: add support/testing for PropertyArrayIndex handling;
        for obj in device.objectList.value[1:]:
            if (
                (int(request.objectIdentifier[1]) == 4194303 or int(request.objectIdentifier[1]) == obj[1])
                and request.objectIdentifier[0] == obj[0]
            ):
                # check if it is a root device or something from object list
                if obj in self.objectIdentifier:

                    # getting properties from objects in object list (self.objectIdentifier)
                    try:
                        property_value = BacpypesServiceObject.read_property_to_any(self.objectIdentifier[obj],
                                                                                    request.propertyIdentifier,
                                                                                    request.propertyArrayIndex)
                    except ExecutionError as e:
                        # return empty string instead of error unknownProperty
                        if e.errorCode == "unknownProperty":
                            datatype = self.objectIdentifier[obj].get_datatype(request.propertyIdentifier)
                            property_value = Any()
                            property_value.cast_in(datatype(None))
                        else:
                            self._response = Error(errorClass=e.errorClass, errorCode=e.errorCode, context=request)
                            break

                    self._response_service = "ComplexAckPDU"
                    self._response = ReadPropertyACK()
                    self._response.pduDestination = PduAddress(address)
                    self._response.apduInvokeID = invoke_key
                    self._response.objectIdentifier = obj
                    self._response.objectName = self.objectIdentifier[obj].objectName
                    self._response.propertyIdentifier = request.propertyIdentifier
                    self._response.propertyValue = property_value
                    break
                else:
                    # getting properties from root device (self.localDevice)
                    try:
                        property_value = BacpypesServiceObject.read_property_to_any(self.localDevice,
                                                                                    request.propertyIdentifier,
                                                                                    request.propertyArrayIndex)
                    except ExecutionError as e:
                        # return empty/None instead of error unknownProperty
                        if e.errorCode == "unknownProperty":
                            datatype = self.localDevice.get_datatype(request.propertyIdentifier)
                            property_value = Any()
                            property_value.cast_in(datatype(None))
                        else:
                            self._response = Error(errorClass=e.errorClass, errorCode=e.errorCode, context=request)
                            break

                    self._response_service = "ComplexAckPDU"
                    self._response = ReadPropertyACK()
                    self._response.pduDestination = PduAddress(address)
                    self._response.apduInvokeID = invoke_key
                    self._response.objectIdentifier = obj
                    # self._response.objectName = ""
                    self._response.propertyIdentifier = request.propertyIdentifier
                    self._response.propertyValue = property_value
                    break

        else:
            logger.info(
                "Bacnet ReadProperty: object %s doesn't exist",
                request.objectIdentifier[0],
            )
            self._response = Error(errorClass="object", errorCode="unknownObject", context=request)

    def readPropertyMultiple(self, request, address, invoke_key, device):
        # Respond to a ReadPropertyMultiple Request.

        # response is a list of read access results (or an error)
        read_access_result_list = []

        # loop through the request
        for read_access_spec in request.listOfReadAccessSpecs:
            # get the object identifier
            objectIdentifier = read_access_spec.objectIdentifier

            obj = None
            # check for wildcard
            if (objectIdentifier == ('device', 4194303) or objectIdentifier == self.localDevice.objectIdentifier) and self.localDevice is not None:
                objectIdentifier = self.localDevice.objectIdentifier
                obj = self.localDevice
            else:
                # get the object
                for device_obj in device.objectList.value[2:]:
                    if objectIdentifier == device_obj:
                        obj = self.objectIdentifier[device_obj]
                        break

            # build a list of result elements
            read_access_result_element_list = []

            # loop through the property references
            for prop_reference in read_access_spec.listOfPropertyReferences:
                # get the property identifier
                propertyIdentifier = prop_reference.propertyIdentifier

                # get the array index (optional)
                propertyArrayIndex = prop_reference.propertyArrayIndex

                # check for special property identifiers
                if propertyIdentifier in ('all', 'required', 'optional'):
                    if not obj:
                        # build a property access error
                        read_result = ReadAccessResultElementChoice()
                        read_result.propertyAccessError = ErrorType(errorClass='object', errorCode='unknownObject')

                        # make an element for this error
                        read_access_result_element = ReadAccessResultElement(
                            propertyIdentifier=propertyIdentifier,
                            propertyArrayIndex=propertyArrayIndex,
                            readResult=read_result,
                        )

                        # add it to the list
                        read_access_result_element_list.append(read_access_result_element)
                    else:
                        for propId, prop in obj._properties.items():

                            # skip propertyList for ReadPropertyMultiple
                            if (propId == 'propertyList'):
                                continue

                            if (propertyIdentifier == 'all'):
                                pass
                            elif (propertyIdentifier == 'required') and (prop.optional):
                                continue
                            elif (propertyIdentifier == 'optional') and (not prop.optional):
                                continue

                            try:
                                # read the specific property
                                read_access_result_element = BacpypesServiceObject.read_property_to_result_element(obj,
                                                                                                                   propId,
                                                                                                                   propertyArrayIndex)
                            except Exception as e:
                                logger.exception("Bacnet exception in readPropertyMultiple")
                                # build a property access error
                                read_result = ReadAccessResultElementChoice()
                                read_result.propertyAccessError = ErrorType(errorClass='object',
                                                                            errorCode='unknownObject')

                                # make an element for this error
                                read_access_result_element = ReadAccessResultElement(
                                    propertyIdentifier=propId,
                                    propertyArrayIndex=propertyArrayIndex,
                                    readResult=read_result,
                                )

                            # check for undefined property
                            if read_access_result_element.readResult.propertyAccessError \
                                    and read_access_result_element.readResult.propertyAccessError.errorCode == 'unknownProperty':
                                continue

                            # add it to the list
                            read_access_result_element_list.append(read_access_result_element)

                else:
                    try:
                        # read the specific property
                        read_access_result_element = BacpypesServiceObject.read_property_to_result_element(obj, propertyIdentifier,
                                                                                     propertyArrayIndex)
                    except Exception as e:
                        # better to respond with error than with nothing
                        logger.exception("Bacnet exception in readPropertyMultiple")
                        # build a property access error
                        read_result = ReadAccessResultElementChoice()
                        read_result.propertyAccessError = ErrorType(errorClass='object',
                                                                    errorCode='unknownObject')

                        # make an element for this error
                        read_access_result_element = ReadAccessResultElement(
                            propertyIdentifier=propertyIdentifier,
                            propertyArrayIndex=propertyArrayIndex,
                            readResult=read_result,
                        )

                    # check for undefined property
                    if read_access_result_element.readResult.propertyAccessError \
                            and read_access_result_element.readResult.propertyAccessError.errorCode == 'unknownProperty':
                        continue
                    # add it to the list
                    read_access_result_element_list.append(read_access_result_element)

            # build a read access result
            read_access_result = ReadAccessResult(
                objectIdentifier=objectIdentifier,
                listOfResults=read_access_result_element_list
            )

            # add it to the list
            read_access_result_list.append(read_access_result)

        # this is a ReadPropertyMultiple ack:
        self._response_service = "ComplexAckPDU"
        self._response = ReadPropertyMultipleACK(context=request)
        # self._response.pduDestination = PduAddress(address)
        # self._response.apduInvokeID = invoke_key
        # self._response.objectIdentifier = obj
        # self._response.objectName = ""
        self._response.listOfReadAccessResults = read_access_result_list

    def indication(self, apdu, address, device):
        """logging the received PDU type and Service request"""
        request = None
        apdu_type = apdu_types.get(apdu.apduType)
        invoke_key = apdu.apduInvokeID
        logger.info(
            "Bacnet PDU received from %s:%d. (%s)",
            address[0],
            address[1],
            apdu_type.__name__,
        )
        if apdu_type.pduType == 0x0:
            # Confirmed request handling
            apdu_service = confirmed_request_types.get(apdu.apduService)
            logger.info(
                "Bacnet indication from %s:%d. (%s)",
                address[0],
                address[1],
                apdu_service.__name__,
            )
            try:
                request = apdu_service()
                request.decode(apdu)
            except (AttributeError, RuntimeError, InvalidParameterDatatype) as e:
                logger.warning("Bacnet indication: Invalid service. Error: %s" % e)
                return
            except bacpypes.errors.DecodingError:
                pass

            for key, value in list(ConfirmedServiceChoice.enumerations.items()):
                if apdu_service.serviceChoice == value:
                    try:
                        getattr(self, key)(request, address, invoke_key, device)
                        break
                    except AttributeError:
                        logger.error("Not implemented Bacnet command")
                        self._response = None
                        return
            else:
                logger.info(
                    "Bacnet indication: Invalid confirmed service choice (%s)",
                    apdu_service.__name__,
                )
                self._response = None
                return

        # Unconfirmed request handling
        elif apdu_type.pduType == 0x1:
            apdu_service = unconfirmed_request_types.get(apdu.apduService)
            logger.info(
                "Bacnet indication from %s:%d. (%s)",
                address[0],
                address[1],
                apdu_service.__name__,
            )
            try:
                request = apdu_service()
                request.decode(apdu)
            except (AttributeError, RuntimeError):
                logger.exception("Bacnet indication: Invalid service.")
                self._response = None
                return
            except bacpypes.errors.DecodingError:
                pass

            for key, value in list(UnconfirmedServiceChoice.enumerations.items()):
                if apdu_service.serviceChoice == value:
                    try:
                        getattr(self, key)(request, address, invoke_key, device)
                        break
                    except AttributeError:
                        logger.error("Not implemented Bacnet command")
                        self._response = None
                        return
            else:
                # Unrecognized services
                logger.info(
                    "Bacnet indication: Invalid unconfirmed service choice (%s)",
                    apdu_service,
                )
                self._response_service = "ErrorPDU"
                self._response = ErrorPDU()
                self._response.pduDestination = PduAddress(address)
                return
        # ignore the following
        elif apdu_type.pduType == 0x2:
            # simple ack pdu
            self._response = None
            return
        elif apdu_type.pduType == 0x3:
            # complex ack pdu
            self._response = None
            return
        elif apdu_type.pduType == 0x4:
            # segment ack
            self._response = None
            return
        elif apdu_type.pduType == 0x5:
            # error pdu
            self._response = None
            return
        elif apdu_type.pduType == 0x6:
            # reject pdu
            self._response = None
            return
        elif apdu_type.pduType == 0x7:
            # abort pdu
            self._response = None
            return
        elif 0x8 <= apdu_type.pduType <= 0xF:
            # reserved
            self._response = None
            return
        else:
            # non-BACnet PDU types
            logger.info("Bacnet Unrecognized service")
            self._response = None
            return

    # socket not actually socket, but DatagramServer with sendto method
    def response(self, response_apdu, address):
        if response_apdu is None:
            return
        apdu = APDU()
        response_apdu.encode(apdu)
        # add missing layers
        # Network layer NPDU
        npdu = NPDU()
        apdu.encode(npdu)
        pdu = PDU(user_data=npdu.pduUserData)
        npdu.encode(pdu)
        # Add Unicast or Broadcast NPDU
        if pdu.pduDestination.addrType == PduAddress.localStationAddr:
            # make an original unicast PDU
            xpdu = OriginalUnicastNPDU(pdu, destination=pdu.pduDestination, user_data=pdu.pduUserData)
        elif pdu.pduDestination.addrType == PduAddress.localBroadcastAddr:
            # make an original broadcast PDU
            xpdu = OriginalBroadcastNPDU(pdu, destination=pdu.pduDestination, user_data=pdu.pduUserData)
        else:
            raise RuntimeError("invalid destination address: {}".format(pdu.pduDestination))
        # Bacnet Virtual Link
        bvlpdu = BVLPDU()
        xpdu.encode(bvlpdu)
        pdu = PDU()
        bvlpdu.encode(pdu)
        if isinstance(response_apdu, RejectPDU) or isinstance(response_apdu, ErrorPDU):
            self.datagram_server.sendto(pdu.pduData, address)
        else:
            apdu_type = apdu_types.get(response_apdu.apduType)
            if pdu.pduDestination == "*:*":
                # broadcast
                # sendto operates under lock
                self.datagram_server.sendto(pdu.pduData, ("", address[1]))
            else:
                # sendto operates under lock
                self.datagram_server.sendto(pdu.pduData, address)
            logger.info(
                "Bacnet response sent to %s (%s:%s)",
                response_apdu.pduDestination,
                apdu_type.__name__,
                self._response_service,
            )
