<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.email" placeholder="Email" style="width: 200px;" class="filter-item" @keyup.enter.native="handleFilter" />
      <el-button class="filter-item" type="primary" icon="el-icon-search" @click="handleFilter">
        Search
      </el-button>
      <el-button class="filter-item" style="margin-left: 10px;" type="primary" icon="el-icon-edit" @click="handleCreate">
        Add
      </el-button>
    </div>

    <el-table v-loading="listLoading" :data="list" border fit highlight-current-row style="width: 100%">
      <el-table-column align="center" label="Index" width="80">
        <template slot-scope="scope">
          {{ scope.$index }}
        </template>
      </el-table-column>

      <el-table-column align="center" label="ID" width="240">
        <template slot-scope="scope">
          {{ scope.row._id }}
        </template>
      </el-table-column>

      <el-table-column width="180px" align="center" label="Email">
        <template slot-scope="{row}">
          <span>{{ row.email }}</span>
        </template>
      </el-table-column>

      <el-table-column min-width="240px" label="Scopes">
        <template slot-scope="{row}">
          <ul v-for="principal in row.scopes" :key="principal">{{ principal }}</ul>
        </template>
      </el-table-column>

      <el-table-column class-name="status-col" align="center" label="is_active" width="110">
        <template slot-scope="{row}">
          <el-tag :type="row.is_active | statusFilter">
            {{ row.is_active }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column class-name="status-col" align="center" label="is_superuser" width="110">
        <template slot-scope="{row}">
          <el-tag :type="row.is_superuser | statusFilter">
            {{ row.is_superuser }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column label="Actions" align="center" width="360" class-name="small-padding fixed-width">
        <template slot-scope="{row,$index}">
          <el-button type="primary" size="mini" @click="handleUpdate(row)">
            Edit
          </el-button>
          <el-button v-if="row.is_active!=true" size="mini" type="success" @click="handleModifyStatus(row,true)">
            Activate
          </el-button>
          <el-button v-if="row.is_active!=false" size="mini" @click="handleModifyStatus(row,false)">
            Deactivate
          </el-button>
          <el-button size="mini" type="danger" @click="handleDelete(row,$index)">
            Delete
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script>
import { getUsers, createUser, updateUser, deleteUser } from '@/api/user'
export default {
  name: 'EditTable',
  filters: {
    statusFilter(status) {
      const statusMap = {
        true: 'success',
        false: 'info'
      }
      return statusMap[status]
    }
  },
  data() {
    return {
      list: null,
      listLoading: true,
      listQuery: {
        page: 1,
        limit: 10
      }
    }
  },
  created() {
    this.getList()
  },
  methods: {
    async getList() {
      this.listLoading = true
      const { data } = await getUsers(this.listQuery)
      const users = data
      this.list = users
      this.total = users.length
      this.listLoading = false
    },
    handleFilter() {
      this.listQuery.page = 1
      this.getList()
    },
    async handleModifyStatus(row, status) {
      this.$message({
        message: '操作Success',
        type: 'success'
      })
      await updateUser(row._id, { 'is_active': status })
    },
    handleCreate() {
      this.resetTemp()
      this.dialogStatus = 'create'
      this.dialogFormVisible = true
      this.$nextTick(() => {
        this.$refs['dataForm'].clearValidate()
      })
    },
    createData() {
      this.$refs['dataForm'].validate((valid) => {
        if (valid) {
          this.temp.email = 'test@example.com'
          createUser(this.temp).then(() => {
            this.list.unshift(this.temp)
            this.dialogFormVisible = false
            this.$notify({
              title: 'Success',
              message: 'Created Successfully',
              type: 'success',
              duration: 2000
            })
          })
        }
      })
    },
    handleUpdate(row) {
      this.temp = Object.assign({}, row) // copy obj
      this.dialogStatus = 'update'
      this.dialogFormVisible = true
      this.$nextTick(() => {
        this.$refs['dataForm'].clearValidate()
      })
    },
    updateData() {
      this.$refs['dataForm'].validate((valid) => {
        if (valid) {
          const tempData = Object.assign({}, this.temp)
          updateUser(tempData).then(() => {
            const index = this.list.findIndex(v => v._id === this.temp._id)
            this.list.splice(index, 1, this.temp)
            this.dialogFormVisible = false
            this.$notify({
              title: 'Success',
              message: 'Update Successfully',
              type: 'success',
              duration: 2000
            })
          })
        }
      })
    },
    async handleDelete(row, index) {
      this.$notify({
        title: 'Success',
        message: 'Delete Successfully',
        type: 'success',
        duration: 2000
      })
      await deleteUser(row._id)
      this.list.splice(index, 1)
    }
  }
}
</script>

<style scoped>
.edit-input {
  padding-right: 100px;
}
.cancel-btn {
  position: absolute;
  right: 15px;
  top: 10px;
}
</style>
