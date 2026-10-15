// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SourceAuthorizedBindings} from "../src/SourceAuthorizedBindings.sol";
interface VmSourceBindings { function addr(uint256) external returns(address); function sign(uint256,bytes32) external returns(uint8,bytes32,bytes32); function warp(uint256) external; function chainId(uint256) external; }
contract SourceAuthorizedBindingsTest {
 VmSourceBindings constant vm=VmSourceBindings(address(uint160(uint256(keccak256("hevm cheat code")))));
 uint256 constant A=0xA11CE; uint256 constant B=0xB0B; uint256 constant BAD=0xD00D;
 bytes32 constant MIG=keccak256("migration"); bytes32 constant SRC=keccak256("source-account-32"); address beneficiary=address(0xBEEF); SourceAuthorizedBindings registry;
 function setUp() public { address[] memory s=new address[](2); s[0]=vm.addr(A); s[1]=vm.addr(B); registry=new SourceAuthorizedBindings(MIG,2,s); }
 function sig(uint256 k,bytes32 d) internal returns(bytes memory){(uint8 v,bytes32 r,bytes32 s)=vm.sign(k,d);return abi.encodePacked(r,s,v);}
 function sigs(uint256 a,uint256 b,bytes32 d) internal returns(bytes[] memory out){out=new bytes[](2);bytes memory sa=sig(a,d);bytes memory sb=sig(b,d);if(vm.addr(a)<vm.addr(b)){out[0]=sa;out[1]=sb;}else{out[0]=sb;out[1]=sa;}}
 function testBindingIsImmutable() public {uint64 exp=uint64(block.timestamp+1 days);bytes32 d=registry.bindingDigest(SRC,beneficiary,exp);registry.registerBinding(SRC,beneficiary,exp,sigs(A,B,d));assert(registry.verifyBinding(SRC,beneficiary));assert(!registry.verifyBinding(SRC,address(0xBAD)));bytes32 bad=registry.bindingDigest(SRC,address(0xBAD),exp);(bool ok,)=address(registry).call(abi.encodeCall(registry.registerBinding,(SRC,address(0xBAD),exp,sigs(A,B,bad))));assert(!ok);}
 function testRejectsUnapprovedAttester() public {uint64 exp=uint64(block.timestamp+1 days);bytes32 d=registry.bindingDigest(SRC,beneficiary,exp);(bool ok,)=address(registry).call(abi.encodeCall(registry.registerBinding,(SRC,beneficiary,exp,sigs(A,BAD,d))));assert(!ok);}
 function testRejectsExpiredBinding() public {uint64 exp=uint64(block.timestamp+1 days);bytes32 d=registry.bindingDigest(SRC,beneficiary,exp);bytes[] memory ss=sigs(A,B,d);vm.warp(uint256(exp)+1);(bool ok,)=address(registry).call(abi.encodeCall(registry.registerBinding,(SRC,beneficiary,exp,ss)));assert(!ok);}
 function testDigestBindsChainId() public {uint64 exp=uint64(block.timestamp+1 days);bytes32 beforeDigest=registry.bindingDigest(SRC,beneficiary,exp);vm.chainId(block.chainid+1);assert(beforeDigest!=registry.bindingDigest(SRC,beneficiary,exp));}
}
