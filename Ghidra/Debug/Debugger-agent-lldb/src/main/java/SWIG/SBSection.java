/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBSection {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBSection(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBSection obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBSection(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBSection() {
    this(lldbJNI.new_SBSection__SWIG_0(), true);
  }

  public SBSection(SBSection rhs) {
    this(lldbJNI.new_SBSection__SWIG_1(SBSection.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBSection_IsValid(swigCPtr, this);
  }

  public String GetName() {
    return lldbJNI.SBSection_GetName(swigCPtr, this);
  }

  public SBSection GetParent() {
    return new SBSection(lldbJNI.SBSection_GetParent(swigCPtr, this), true);
  }

  public SBSection FindSubSection(String sect_name) {
    return new SBSection(lldbJNI.SBSection_FindSubSection(swigCPtr, this, sect_name), true);
  }

  public long GetNumSubSections() {
    return lldbJNI.SBSection_GetNumSubSections(swigCPtr, this);
  }

  public SBSection GetSubSectionAtIndex(long idx) {
    return new SBSection(lldbJNI.SBSection_GetSubSectionAtIndex(swigCPtr, this, idx), true);
  }

  public java.math.BigInteger GetFileAddress() {
    return lldbJNI.SBSection_GetFileAddress(swigCPtr, this);
  }

  public java.math.BigInteger GetLoadAddress(SBTarget target) {
    return lldbJNI.SBSection_GetLoadAddress(swigCPtr, this, SBTarget.getCPtr(target), target);
  }

  public java.math.BigInteger GetByteSize() {
    return lldbJNI.SBSection_GetByteSize(swigCPtr, this);
  }

  public java.math.BigInteger GetFileOffset() {
    return lldbJNI.SBSection_GetFileOffset(swigCPtr, this);
  }

  public java.math.BigInteger GetFileByteSize() {
    return lldbJNI.SBSection_GetFileByteSize(swigCPtr, this);
  }

  public SBData GetSectionData() {
    return new SBData(lldbJNI.SBSection_GetSectionData__SWIG_0(swigCPtr, this), true);
  }

  public SBData GetSectionData(java.math.BigInteger offset, java.math.BigInteger size) {
    return new SBData(lldbJNI.SBSection_GetSectionData__SWIG_1(swigCPtr, this, offset, size), true);
  }

  public SectionType GetSectionType() {
    return SectionType.swigToEnum(lldbJNI.SBSection_GetSectionType(swigCPtr, this));
  }

  public long GetPermissions() {
    return lldbJNI.SBSection_GetPermissions(swigCPtr, this);
  }

  public long GetTargetByteSize() {
    return lldbJNI.SBSection_GetTargetByteSize(swigCPtr, this);
  }

  public boolean GetDescription(SBStream description) {
    return lldbJNI.SBSection_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description);
  }

  public String __str__() {
    return lldbJNI.SBSection___str__(swigCPtr, this);
  }

}
