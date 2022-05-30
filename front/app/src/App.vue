<template>
  <img alt="Vue logo" src="./assets/logo.png">
  
  <div>
    <h4>xx 원룸</h4>
    <p>{{ price1 }} 만원</p>
  </div>
  <div>
    <h4>xx 원룸</h4>
    <p>{{ price2 }} 만원</p>
  </div>

  <div class="menu">
    <a>home</a>  
  </div>]

</template>

<script>


export default {
  name: 'App',
  data() {
    return {
      price1 : 50,
      price2 : 60,
    }
  },
  components: {
    
  }
}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}

.menu{ 
  background-color: darkslateblue;
}
</style>
