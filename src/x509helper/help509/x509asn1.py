#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Copyright (C) 2018
    Adam Greene <copyright@mzpqnxow.com>
Please see LICENSE or LICENSE.md for terms

Python OpenSSL bindings have problems parsing custom OIDs in the Subject
field. Without doing the ASN.1 parsing ourselves all we get in the Subject field of some
certificates is 'Undef'

This is the work around that parses the ASN.1 and gives a list of OIDs that can later be
resolved to readable text. This is so that it can be extended in the future with exotic
certificates.
"""
import pyasn1

MAX = 64


class DirectoryString(pyasn1.type.univ.Choice):
    componentType = pyasn1.type.namedtype.NamedTypes(
        pyasn1.type.namedtype.NamedType(
            'teletexString', pyasn1.type.char.TeletexString().subtype(
                subtypeSpec=pyasn1.type.constraint.ValueSizeConstraint(1, MAX))),
        pyasn1.type.namedtype.NamedType(
            'printableString',
            pyasn1.type.char.PrintableString().subtype(
                subtypeSpec=pyasn1.type.constraint.ValueSizeConstraint(1, MAX))),
        pyasn1.type.namedtype.NamedType(
            'universalString', pyasn1.type.char.UniversalString().subtype(
                subtypeSpec=pyasn1.type.constraint.ValueSizeConstraint(1, MAX))),
        pyasn1.type.namedtype.NamedType(
            'utf8String', pyasn1.type.char.UTF8String().subtype(
                subtypeSpec=pyasn1.type.constraint.ValueSizeConstraint(1, MAX))),
        pyasn1.type.namedtype.NamedType(
            'bmpString', pyasn1.type.char.BMPString().subtype(
                subtypeSpec=pyasn1.type.constraint.ValueSizeConstraint(1, MAX))),
        pyasn1.type.namedtype.NamedType(
            'ia5String', pyasn1.type.char.IA5String().subtype(
                subtypeSpec=pyasn1.type.constraint.ValueSizeConstraint(1, MAX))))


class AttributeValue(DirectoryString):
    pass


class AttributeType(pyasn1.type.univ.ObjectIdentifier):
    pass


class AttributeTypeAndValue(pyasn1.type.univ.Sequence):
    componentType = pyasn1.type.namedtype.NamedTypes(
        pyasn1.type.namedtype.NamedType('type', AttributeType()),
        pyasn1.type.namedtype.NamedType('value', AttributeValue()))


class RelativeDistinguishedName(pyasn1.type.univ.SetOf):
    componentType = AttributeTypeAndValue()


class RDNSequence(pyasn1.type.univ.SequenceOf):
    componentType = RelativeDistinguishedName()


class Name(pyasn1.type.univ.Choice):
    componentType = pyasn1.type.namedtype.NamedTypes(
        pyasn1.type.namedtype.NamedType('', RDNSequence()))
