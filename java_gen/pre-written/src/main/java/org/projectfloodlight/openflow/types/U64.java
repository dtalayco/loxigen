/**
 *    Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior
 *    University
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package org.projectfloodlight.openflow.types;

import java.math.BigInteger;

import org.jboss.netty.buffer.ChannelBuffer;
import org.projectfloodlight.openflow.protocol.Writeable;

import com.google.common.primitives.UnsignedLongs;

public class U64 implements Writeable, OFValueType<U64> {
    private static final long UNSIGNED_MASK = 0x7fffffffffffffffL;
    private final static long ZERO_VAL = 0;
    public final static U64 ZERO = new U64(ZERO_VAL);

    private final long raw;

    protected U64(final long raw) {
        this.raw = raw;
    }

    public static U64 of(long raw) {
        return ofRaw(raw);
    }

    public static U64 ofRaw(final long raw) {
        if(raw == ZERO_VAL)
            return ZERO;
        return new U64(raw);
    }

    public static U64 parseHex(String hex) {
        return new U64(new BigInteger(hex, 16).longValue());
    }

    public long getValue() {
        return raw;
    }

    public BigInteger getBigInteger() {
        BigInteger bigInt = BigInteger.valueOf(raw & UNSIGNED_MASK);
        if (raw < 0) {
          bigInt = bigInt.setBit(Long.SIZE - 1);
        }
        return bigInt;
    }

    @Override
    public String toString() {
        return getBigInteger().toString();
    }

    public static BigInteger f(final long value) {
        BigInteger bigInt = BigInteger.valueOf(value & UNSIGNED_MASK);
        if (value < 0) {
          bigInt = bigInt.setBit(Long.SIZE - 1);
        }
        return bigInt;
    }

    public static long t(final BigInteger l) {
        return l.longValue();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (raw ^ (raw >>> 32));
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        U64 other = (U64) obj;
        if (raw != other.raw)
            return false;
        return true;
    }

    @Override
    public int getLength() {
        return 8;
    }

    @Override
    public U64 applyMask(U64 mask) {
        return ofRaw(raw & mask.raw);
    }

    @Override
    public void writeTo(ChannelBuffer bb) {
        bb.writeLong(raw);
    }

    @Override
    public int compareTo(U64 o) {
        return UnsignedLongs.compare(raw, o.raw);
    }

}
