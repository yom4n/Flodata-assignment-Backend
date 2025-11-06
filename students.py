from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from bson import ObjectId
from datetime import datetime

import database
from auth import get_current_user, get_current_admin
from schemas import StudentCreate, StudentOut, UserOut

router = APIRouter(
    prefix="/api/v1/students",
    tags=["Students"],
    dependencies=[Depends(get_current_user)]
)

@router.get("/", response_model=List[StudentOut])
async def list_students(
    current_user: UserOut = Depends(get_current_user)
):
    """
    List all students.
    Accessible by both regular users and admins.
    """
    students = []
    async for student in database.student_collection.find():
        student["id"] = str(student["_id"])
        students.append(StudentOut(**student))
    return students

@router.post("/", response_model=StudentOut, status_code=status.HTTP_201_CREATED)
async def create_student(
    student_data: StudentCreate,
    current_user: UserOut = Depends(get_current_admin)
):
    """
    Create a new student.
    Only accessible by admin users.
    """
    # Check if student with the same roll number already exists
    existing_student = await database.student_collection.find_one(
        {"roll_number": student_data.roll_number}
    )
    if existing_student:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Student with roll number {student_data.roll_number} already exists"
        )
    
    # Prepare student document
    student_dict = student_data.model_dump()
    student_dict.update({
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    })
    
    # Insert new student
    result = await database.student_collection.insert_one(student_dict)
    created_student = await database.student_collection.find_one({"_id": result.inserted_id})
    
    return StudentOut(**created_student)

@router.put("/{roll_number}", response_model=StudentOut)
async def update_student(
    roll_number: str,
    student_data: StudentCreate,
    current_user: UserOut = Depends(get_current_admin)
):
    """
    Update an existing student by roll number.
    Only accessible by admin users.
    """
    # Check if student exists
    existing_student = await database.student_collection.find_one(
        {"roll_number": roll_number}
    )
    if not existing_student:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Student with roll number {roll_number} not found"
        )
    
    # Check if new roll number conflicts with existing students
    if roll_number != student_data.roll_number:
        roll_number_exists = await database.student_collection.find_one(
            {"roll_number": student_data.roll_number}
        )
        if roll_number_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Another student with roll number {student_data.roll_number} already exists"
            )
    
    # Prepare update data
    update_data = student_data.model_dump()
    update_data["updated_at"] = datetime.utcnow()
    
    # Update student
    await database.student_collection.update_one(
        {"roll_number": roll_number},
        {"$set": update_data}
    )
    
    # Return updated student
    updated_student = await database.student_collection.find_one(
        {"roll_number": student_data.roll_number}
    )
    return StudentOut(**updated_student)

@router.delete("/{roll_number}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_student(
    roll_number: str,
    current_user: UserOut = Depends(get_current_admin)
):
    """
    Delete a student by roll number.
    Only accessible by admin users.
    """
    result = await database.student_collection.delete_one({"roll_number": roll_number})
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Student with roll number {roll_number} not found"
        )
    return {"message": "Student deleted successfully"}